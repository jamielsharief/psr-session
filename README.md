# PSR-7/PSR-15 Sessions 

## Problems

1. Currently PHP sessions are not compatible with `PSR-7`
2. The session object is widely used but there is no standard. A session spec would actually help solve a number of problems, including:
    - standardizing between frameworks
    - using other peoples implemenations easily
    - swapping out types of implemenations so if you want to use Swoole, you can move away from the PHP sessions and switch to a Redis handler
    - Lots of companies like to move their controller logic into reusuable services which would be much easier with a session spec.
3. Another important part of this PSR, I believe, is for a standard way to set and get the Session object on the `ServerRequestInterface` object, without this feature, I think it would be incomplete.

## Security

- Security is an issue and a potential complexity. I believe by also standardizing the hooks into the session lifecycle, such as `startup` and `shutdown` this will bring enough flexability into the session spec, so developers are able to deal with security related issues such as validating the session ID perhaps or deleting previous data etc.
- Take into consideration OWASP recommendations, including:
    - the default session ID name to be `id` to prevent `Session ID Name Fingerprinting`
    - the session ID should be at least 128 bits (16 bytes)
    - and other recommendations such as cookie settings etc.

## Objectives

- User can set, get, check, clear or destroy sessions completely
- Middleware needs to start, close sessions, set the id, and get the id once the storage creates the ID or regenerates the ID so that it can write to the cookie
- Middleware also needs to know if the session was destroyed so it can delete the cookie
- Hooks into the session lifecycle for security purposes, needs to be handled
- It needs to work with various types of storage, e.g PHP Sessions, Redis, JWT tokens and single long-running processes e.g. Swoole.

## Inital Concept

```php
interface HttpSessionInterface
{
    /**
     * Sets a value in the session
     *
     * @param string $key
     * @param mixed $value
     * @return void
     */
    public function set(string $key, $value) : void;

    /**
     * Gets a value from the session
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public function get(string $key, $default = null);

    /**
     * Removes a value from the session
     *
     * @param string $key
     * @return void
     */
    public function unset(string $key): void;

    /**
     * Checks if the session has the key
     *
     * @param string $key
     * @return boolean
     */
    public function has(string $key): bool;

    /**
     * Clears the contents of the session
     *
     * @return void
     */
    public function clear(): void;

    /**
     * Destroy the current session
     *
     * @return void
     */
    public function destroy(): void;

    /**
     * Starts a session and loads data from storage
     *
     * @param string|null $sessionId
     * @return boolean
     */
    public function start(?string $sessionId = null): bool;

    /**
     * Closes a session and writes to storage
     *
     * @return boolean
     */
    public function close(): bool;

    /**
     * Get the session Id, null means session was destroyed (or not started).
     *
     * @param string|null $sessionId
     * @return string|null
     */
    public function getId(): ?string;

    /**
     * Informs the session object to regenerate the session ID for the existing session data
     *
     * @return boolean
     */
    public function regenerateId(): bool;
}
```

With regards to standardizing the setting and getting the session object on `ServerRequestInterface` object

```php
interface ServerRequestSessionInterface 
{
    public function setSession(HttpSessionInterface $session): void;
    public function getSession(): HttpSessionInterface;
}
```

- not sure about the naming though if this interface is used
- hopefully this allows to extend and not break anything
- A potential issue here is if the session was not added, do you throw an exception, return `null` etc?

## Example Middleware

```php
class SessionMiddleware implements MiddlewareInterface
{
    protected HttpSessionInterface $session;

    protected string $cookieName = 'id'; // OWASP recommendation
    protected int $timeout = 900; // 15 minutes
    protected string $sameSite = 'lax';

    public function __construct(HttpSessionInterface $session)
    {
        $this->session = $session;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $sessionId = $this->getSessionId($request); // Get value from cookie, session ID or perhaps JWT token?

        $this->session->start($sessionId);

        $response = $handler->handle($request->withAttribute('session', $this->session));

        // close session if still open, user may have destroyed or closed manualy
        $this->session->close(); 

        return $this->addCookieToResponse($request, $response);
    }

    /**
     * If the session was destroyed, there will be no id, so delete delete delete. If the 
     * session ID was regenerated, then the cookie needs to be updated and added a quick 
     * timeout feature.
     */
    private function addCookieToResponse(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $wasDestroyed = is_null($this->session->getId());
        $cookieValue = $wasDestroyed ? '' : $this->session->getId();
        $cookieExpires = $wasDestroyed ? time() - 3600 : time() + $this->timeout;

        return $response->withAddedHeader(
             'Set-Cookie', $this->createCookieString($cookieValue, $cookieExpires, $request)
         );
    }

    private function getSessionId(ServerRequestInterface $request): ?string
    {
        $cookies = $request->getCookieParams();

        return $cookies[$this->cookieName] ?? null;
    }

    private function createCookieString(string $sessionId, int $expires, ServerRequestInterface $request): string
    {
        return sprintf(
            '%s=%s; expires=%s; path=%s; samesite=%s;%s httponly',
            $this->cookieName,
            $sessionId,
            gmdate('D, d M Y H:i:s T', $expires),
            ini_get('session.cookie_path'),  // Important!
            $this->sameSite,
            $request->getUri()->getScheme() === 'https' ? ' secure;' : null
        ) ;
    }
}
```

Here is simple example to demonstrate the concept

```php
class PhpSession implements HttpSessionInterface
{
    private ?string $id = null;
    private array $session = [];
    private bool $isRegenerated = false;
    private bool $isStarted = false;

    public function start(?string $id = null): bool
    {
        if ($this->isStarted) {
            return false;
        }

        $this->id = $id ?: $this->createId();

        session_id($this->id);

        // Disable the PHP cookie features, credit to @pmjones for this
        $this->isStarted = session_start([
            'use_cookies' => false,
            'use_only_cookies' => false,
            'use_trans_sid' => false
        ]);

        $this->session = $_SESSION ?? [];

        return $this->isStarted;
    }

    public function set(string $key, $value): void
    {
        $this->session[$key] = $value;
    }

    public function get(string $key, $default = null)
    {
        return $this->session[$key] ?? $default;
    }

    public function unset(string $key): void
    {
        unset($this->session[$key]);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->session);
    }

    public function clear(): void
    {
        $this->session = [];
    }

    public function destroy(): void
    {
        $this->session = [];
        $this->close();
        $this->id = null;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    public function regenerateId(): bool
    {
        $this->id = $this->createId();
        $this->isRegenerated = true;

        return true;
    }

    public function createId(): string
    {
        return bin2hex(random_bytes(16)); // OWASP recommendation
    }

    public function close(): bool
    {
        if ($this->isStarted === false) {
            return false;
        }

        //  I remember there were issues with overwriting the $_SESSION variable
        $removed = array_diff(array_keys($_SESSION), array_keys($this->session));

        foreach ($this->session as $key => $value) {
            $_SESSION[$key] = $value;
        }

        foreach ($removed as  $key) {
            unset($_SESSION[$key]);
        }
        $closed = session_write_close();

        $this->isStarted = $closed === false;

        return $this->isRegenerated ? $this->regenerateSessionData() : $closed;
    }

    /**
     * Copy session data to new ID
     *
     * @return boolean
     */
    private function regenerateSessionData(): bool
    {
        $this->isRegenerated = false;
        $session = $_SESSION; // data still seems to be here
        $this->start($this->id); // start session with new session ID
        $this->session = $session; // kansas city shuffle

        return $this->close(); // save
    }
}
```

## Resources

- https://paul-m-jones.com/post/2016/04/12/psr-7-and-session-cookies/
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://github.com/mezzio/mezzio-session
- https://github.com/yiisoft/session