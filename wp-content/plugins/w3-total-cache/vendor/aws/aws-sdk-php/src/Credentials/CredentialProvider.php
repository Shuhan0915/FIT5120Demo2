<?php
namespace Aws\Credentials;

use Aws;
use Aws\Api\DateTimeResult;
use Aws\CacheInterface;
use Aws\Exception\CredentialsException;
use Aws\Sts\StsClient;
use GuzzleHttp\Promise;

/**
 * Credential providers are functions that accept no arguments and return a
 * promise that is fulfilled with an {@see \Aws\Credentials\CredentialsInterface}
 * or rejected with an {@see \Aws\Exception\CredentialsException}.
 *
 * <code>
 * use Aws\Credentials\CredentialProvider;
 * $provider = CredentialProvider::defaultProvider();
 * // Returns a CredentialsInterface or throws.
 * $creds = $provider()->wait();
 * </code>
 *
 * Credential providers can be composed to create credentials using conditional
 * logic that can create different credentials in different environments. You
 * can compose multiple providers into a single provider using
 * {@see Aws\Credentials\CredentialProvider::chain}. This function accepts
 * providers as variadic arguments and returns a new function that will invoke
 * each provider until a successful set of credentials is returned.
 *
 * <code>
 * // First try an INI file at this location.
 * $a = CredentialProvider::ini(null, '/path/to/file.ini');
 * // Then try an INI file at this location.
 * $b = CredentialProvider::ini(null, '/path/to/other-file.ini');
 * // Then try loading from environment variables.
 * $c = CredentialProvider::env();
 * // Combine the three providers together.
 * $composed = CredentialProvider::chain($a, $b, $c);
 * // Returns a promise that is fulfilled with credentials or throws.
 * $promise = $composed();
 * // Wait on the credentials to resolve.
 * $creds = $promise->wait();
 * </code>
 */
class CredentialProvider
{
    const ENV_ARN = 'AWS_ROLE_ARN';
    const ENV_KEY = 'AWS_ACCESS_KEY_ID';
    const ENV_PROFILE = 'AWS_PROFILE';
    const ENV_ROLE_SESSION_NAME = 'AWS_ROLE_SESSION_NAME';
    const ENV_SECRET = 'AWS_SECRET_ACCESS_KEY';
    const ENV_SESSION = 'AWS_SESSION_TOKEN';
    const ENV_TOKEN_FILE = 'AWS_WEB_IDENTITY_TOKEN_FILE';
    const ENV_SHARED_CREDENTIALS_FILE = 'AWS_SHARED_CREDENTIALS_FILE';

    /**
     * Create a default credential provider that
     * first checks for environment variables,
     * then checks for assumed role via web identity,
     * then checks for cached SSO credentials from the CLI,
     * then check for credential_process in the "default" profile in ~/.aws/credentials,
     * then checks for the "default" profile in ~/.aws/credentials,
     * then for credential_process in the "default profile" profile in ~/.aws/config,
     * then checks for "profile default" profile in ~/.aws/config (which is
     * the default profile of AWS CLI),
     * then tries to make a GET Request to fetch credentials if ECS environment variable is presented,
     * finally checks for EC2 instance profile credentials.
     *
     * This provider is automatically wrapped in a memoize function that caches
     * previously provided credentials.
     *
     * @param array $config Optional array of ecs/instance profile credentials
     *                      provider options.
     *
     * @return callable
     */
    public static function defaultProvider(array $config = [])
    {
        $cacheable = [
            'web_identity',
            'sso',
            'process_credentials',
            'process_config',
            'ecs',
            'instance'
        ];

        $defaultChain = [
            'env' => self::env(),
            'web_identity' => self::assumeRoleWithWebIdentityCredentialProvider($config),
        ];
        if (
            !isset($config['use_aws_shared_config_files'])
            || $config['use_aws_shared_config_files'] !== false
        ) {
            $defaultChain['sso'] = self::sso(
                'profile default',
                self::getHomeDir() . '/.aws/config',
                $config
            );
            $defaultChain['process_credentials'] = self::process();
            $defaultChain['ini'] = self::ini();
            $defaultChain['process_config'] = self::process(
                'profile default',
                self::getHomeDir() . '/.aws/config'
            );
            $defaultChain['ini_config'] = self::ini(
                'profile default',
                self::getHomeDir() . '/.aws/config'
            );
        }

        $shouldUseEcsCredentialsProvider = getenv(EcsCredentialProvider::ENV_URI);
        // getenv() is not thread safe - fall back to $_SERVER
        if ($shouldUseEcsCredentialsProvider === false) {
            $shouldUseEcsCredentialsProvider = isset($_SERVER[EcsCredentialProvider::ENV_URI])
                ? $_SERVER[EcsCredentialProvider::ENV_URI]
                : false;
        }

        if (!empty($shouldUseEcsCredentialsProvider)) {
            $defaultChain['ecs'] = self::ecsCredentials($config);
        } else {
            $defaultChain['instance'] = self::instanceProfile($config);
        }

        if (isset($config['credentials'])
            && $config['credentials'] instanceof CacheInterface
        ) {
            foreach ($cacheable as $provider) {
                if (isset($defaultChain[$provider])) {
                    $defaultChain[$provider] = self::cache(
                        $defaultChain[$provider],
                        $config['credentials'],
                        'aws_cached_' . $provider . '_credentials'
                    );
                }
            }
        }

        return self::memoize(
            call_user_func_array(
                'self::chain',
                array_values($defaultChain)
            )
        );
    }

    /**
     * Create a credential provider function from a set of static credentials.
     *
     * @param CredentialsInterface $creds
     *
     * @return callable
     */
    public static function fromCredentials(CredentialsInterface $creds)
    {
        $promise = Promise\promise_for($creds);

        return function () use ($promise) {
            return $promise;
        };
    }

    /**
     * Creates an aggregate credentials provider that invokes the provided
     * variadic providers one after the other until a provider returns
     * credentials.
     *
     * @return callable
     */
    public static function chain()
    {
        $links = func_get_args();
        if (empty($links)) {
            throw new \InvalidArgumentException('No providers in chain');
        }

        return function () use ($links) {
            /** @var callable $parent */
            $parent = array_shift($links);
            $promise = $parent();
            while ($next = array_shift($links)) {
                $promise = $promise->otherwise($next);
            }
            return $promise;
        };
    }

    /**
     * Wraps a credential provider and caches previously provided credentials.
     *
     * Ensures that cached credentials are refreshed when they expire.
     *
     * @param callable $provider Credentials provider function to wrap.
     *
     * @return callable
     */
    public static function memoize(callable $provider)
    {
        return function () use ($provider) {
            static $result;
            static $isConstant;

            // Constant credentials will be returned constantly.
            if ($isConstant) {
                return $result;
            }

            // Create the initial promise that will be used as the cached value
            // until it expires.
            if (null === $result) {
                $result = $provider();
            }

            // Return credentials that could expire and refresh when needed.
            return $result
                ->then(function (CredentialsInterface $creds) use ($provider, &$isConstant, &$result) {
                    // Determine if these are constant credentials.
                    if (!$creds->getExpiration()) {
                        $isConstant = true;
                        return $creds;
                    }

                    // Refresh expired credentials.
                    if (!$creds->isExpired()) {
                        return $creds;
                    }
                    // Refresh the result and forward the promise.
                    return $result = $provider();
                })
                ->otherwise(function($reason) use (&$result) {
                    // Cleanup rejected promise.
                    $result = null;
                    return new Promise\RejectedPromise($reason);
                });
        };
    }

    /**
     * Wraps a credential provider and saves provided credentials in an
     * instance of Aws\CacheInterface. Forwards calls when no credentials found
     * in cache and updates cache with the results.
     *
     * @param callable $provider Credentials provider function to wrap
     * @param CacheInterface $cache Cache to store credentials
     * @param string|null $cacheKey (optional) Cache key to use
     *
     * @return callable
     */
    public static function cache(
        callable $provider,
        CacheInterface $cache,
        $cacheKey = null
    ) {
        $cacheKey = $cacheKey ?: 'aws_cached_credentials';

        return function () use ($provider, $cache, $cacheKey) {
            $found = $cache->get($cacheKey);
            if ($found instanceof CredentialsInterface && !$found->isExpired()) {
                return Promise\promise_for($found);
            }

            return $provider()
                ->then(function (CredentialsInterface $creds) use (
                    $cache,
                    $cacheKey
                ) {
                    $cache->set(
                        $cacheKey,
                        $creds,
                        null === $creds->getExpiration() ?
                            0 : $creds->getExpiration() - time()
                    );

                    return $creds;
                });
        };
    }

    /**
     * Provider that creates credentials from environment variables
     * AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN.
     *
     * @return callable
     */
    public static function env()
    {
        return function () {
            // Use credentials from environment variables, if available
            $key = getenv(self::ENV_KEY);
            $secret = getenv(self::ENV_SECRET);
            if ($key && $secret) {
                return Promise\promise_for(
                    new Credentials($key, $secret, getenv(self::ENV_SESSION) ?: NULL)
                );
            }

            return self::reject('Could not find environment variable '
                . 'credentials in ' . self::ENV_KEY . '/' . self::ENV_SECRET);
        };
    }

    /**
     * Credential provider that creates credentials using instance profile
     * credentials.
     *
     * @param array $config Array of configuration data.
     *
     * @return InstanceProfileProvider
     * @see Aws\Credentials\InstanceProfileProvider for $config details.
     */
    public static function instanceProfile(array $config = [])
    {
        return new InstanceProfileProvider($config);
    }

    /**
     * Credential provider that retrieves cached SSO credentials from the CLI
     *
     * @return callable
     */
    public static function sso($ssoProfileName, $filename = null, $config = [])
    {
        $filename = $filename ?: (self::getHomeDir() . '/.aws/config');

        return function () use ($ssoProfileName, $filename, $config) {
            if (!is_readable($filename)) {
                return self::reject("Cannot read credentials from $filename");
            }
            $profiles = self::loadProfiles($filename);
            if (!isset($profiles[$ssoProfileName])) {
                return self::reject("Profile {$ssoProfileName} does not exist in {$filename}.");
            }
            $ssoProfile = $profiles[$ssoProfileName];
            if (empty($ssoProfile['sso_start_url'])
                || empty($ssoProfile['sso_region'])
                || empty($ssoProfile['sso_account_id'])
                || empty($ssoProfile['sso_role_name'])
            ) {
                return self::reject(
                    "Profile {$ssoProfileName} in {$filename} must contain the following keys: "
                    . "sso_start_url, sso_region, sso_account_id, and sso_role_name."
                );
            }

            $tokenLocation = self::getHomeDir()
                . '/.aws/sso/cache/'
                . utf8_encode(sha1($ssoProfile['sso_start_url']))
                . ".json";

            if (!is_readable($tokenLocation)) {
                return self::reject("Unable to read token file at $tokenLocation");
            }

            $tokenData = json_decode(file_get_contents($tokenLocation), true);
            if (empty($tokenData['accessToken']) || empty($tokenData['expiresAt'])) {
                return self::reject(
                    "Token file at {$tokenLocation} must contain an access token and an expiration"
                );
            }
            try {
                $expiration = (new DateTimeResult($tokenData['expiresAt']))->getTimestamp();
            } catch (\Exception $e) {
                return self::reject("Cached SSO credentials returned an invalid expiration");
            }
            $now = time();
            if ($expiration < $now) {
                return self::reject("Cached SSO credentials returned expired credentials");
            }

            $ssoClient = null;
            if (empty($config['ssoClient'])) {
                $ssoClient = new Aws\SSO\SSOClient([
                    'region' => $ssoProfile['sso_region'],
                    'version' => '2019-06-10',
                    'credentials' => false
                ]);
            } else {
                $ssoClient = $config['ssoClient'];
            }
            $ssoResponse = $ssoClient->getRoleCredent