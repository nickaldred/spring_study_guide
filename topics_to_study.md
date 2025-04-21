# Study schedule

## Schedule - TODO

- Redo all exams
- Go over topics that you study with on vmware site
- Redo all exams
- Do questions online you haven't done before
- Use gpt as a test?
- Get set up for test

## Topics to Study

- Spring HATEOAS

- Enabling the execution of SQL scripts prior to running test methods.

- Destroy methods are called in the same order:

    ```txt
    Methods annotated with @PreDestroy

    destroy() as defined by the DisposableBean callback interface

    A custom configured destroy() method
    ```

## Notes

### Spring Boot Actuator

#### 🔹 What is Spring Boot Actuator?

- Provides **production-ready features** to help monitor and manage applications.
- Exposes **endpoints** via HTTP (or JMX) for metrics, health checks, etc.
- Integrates with **Micrometer** for metrics collection.

---

#### 🔹 Key Dependencies

```xml
<!-- Add this in pom.xml -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

```groovy
// For Gradle
implementation 'org.springframework.boot:spring-boot-starter-actuator'
```

---

#### 🔹 Common Actuator Endpoints

| Endpoint               | Description                              |
|------------------------|------------------------------------------|
| `/actuator/health`     | Shows application health (UP/DOWN)       |
| `/actuator/info`       | Displays arbitrary app info              |
| `/actuator/metrics`    | Exposes application metrics              |
| `/actuator/env`        | View environment properties              |
| `/actuator/beans`      | Shows all Spring beans                   |
| `/actuator/mappings`   | Shows all URL mappings                   |
| `/actuator/loggers`    | View/change log levels at runtime        |
| `/actuator/threaddump` | JVM thread dump                          |

---

#### 🔹 Endpoint statuses

- By default, Spring Boot Actuator defines four different values as the health Status:

    ```txt
    UP — The component or subsystem is working as expected
    DOWN — The component is not working
    OUT_OF_SERVICE — The component is out of service temporarily    
    UNKNOWN — The component state is unknown
    ```

---

#### 🔹 Enabling Endpoints

- By default, only `/health` and `/info` are enabled.
- Configure in `application.properties` or `application.yml`:

```properties
management.endpoints.web.exposure.include=*
```

---

#### 🔹 Security

- Actuator endpoints can be **secured** using Spring Security.
- Customize access control:

```properties
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=always
```

- Secure endpoints via role-based access in your `SecurityConfig`.

---

#### 🔹 Custom Info Properties

- Add custom entries to `/actuator/info`:

```properties
info.app.name=MyApp
info.app.description=Spring Boot App
```

- Access via: `/actuator/info`

---

#### 🔹 Health Indicators

- Built-in indicators: `db`, `diskSpace`, `ping`, `redis`, etc.
- Custom indicators:

```java
@Component
public class MyHealthIndicator implements HealthIndicator {
    @Override
    public Health health() {
        return Health.up().withDetail("custom", "all good").build();
    }
}
```

---

#### 🔹 Metrics with Micrometer

- Micrometer is the **metrics facade** used by Actuator.
- Supports multiple backends: Prometheus, Datadog, New Relic, etc.
- Metric examples:
  - `jvm.memory.used`
  - `http.server.requests`
  - `system.cpu.usage`

---

#### 🔹 Custom Metrics Example

```java
@Autowired
private MeterRegistry meterRegistry;

@PostConstruct
public void init() {
    meterRegistry.counter("custom.counter").increment();
}
```

---

#### 📊 Micrometer Metric Types in Spring Boot Actuator

| Type               | Best For                         | Increments? | Measures Duration? |
|--------------------|----------------------------------|-------------|---------------------|
| `Counter`          | Count of events (e.g. logins)    | ✅          | ❌                  |
| `Gauge`            | Varying value (e.g. queue size)  | ❌          | ❌                  |
| `Timer`            | Time per operation               | ✅          | ✅                  |
| `DistributionSummary` | Data sizes, value distribution | ✅         | ❌                  |
| `LongTaskTimer`    | Long-running tasks               | ✅          | ✅                  |

---

#### 🔹 Management Port and Context

- Run actuator endpoints on a **different port**:

```properties
management.server.port=8081
```

- Set different base path:

```properties
management.endpoints.web.base-path=/manage
```

---

#### 🔹 JMX Support

- Expose endpoints via JMX:

```properties
spring.jmx.enabled=true
management.endpoints.jmx.exposure.include=*
```

#### ✅ Best Practices

- Limit exposed endpoints in production (`include=health,info`)
- Use `management.endpoint.health.show-details=when-authorized`
- Integrate with Prometheus/Grafana for observability
- Use actuators in cloud-native deployments (e.g., k8s probes)

---

🎯 **Exam Tip**: Know how to expose endpoints, use different metric types, and integrate Actuator with Micrometer for observability.

### Spring Core

### Spring AOP

- **AOP**: Aspect-Oriented Programming – separates cross-cutting concerns.
- **Cross-cutting Concerns**: Logging, security, transactions, etc.
- **Aspect**: Module encapsulating cross-cutting logic.
- **Advice**: Action taken at a specific point in program (join point).
- **Join Point**: Specific execution point (e.g., method call).
- **Pointcut**: Expression that matches join points.
- **Weaving**: Applying aspects to target objects.
- **Runtime Proxies**: Spring AOP uses proxies (JDK or CGLIB).

---

#### 🔹 Types of Advice

- `@Before` – Runs before method execution.
- `@After` – Runs after method execution (regardless of outcome).
- `@AfterReturning` – Runs after successful execution.
- `@AfterThrowing` – Runs if an exception is thrown.
- `@Around` – Wraps the method execution (manual control via `proceed()`).

---

#### 🔹 Declaring Aspects

- `@Aspect` – Marks a class as an aspect.
- `@Component` – Makes aspect a Spring-managed bean.
- `@EnableAspectJAutoProxy` – Enables AOP support in `@Configuration`.

---

#### 🔹 Defining Pointcuts

- **execution**: Match method signatures  
  `execution(* com.example.service.*.*(..))`
- **within**: Match all methods in classes under a package  
  `within(com.example..*)`
- **@annotation**: Match methods annotated with a specific annotation  
  `@annotation(com.example.MyAnnotation)`
- **args, this, target**: Match based on object/arg types

---

#### 🔹 Around Advice

- Signature:  
  `public Object around(ProceedingJoinPoint pjp) throws Throwable`
- Use `pjp.proceed()` to execute the target method.
- Can modify arguments and return values.

---

#### 🔹 AOP Proxy Mechanisms

- **JDK Dynamic Proxy** – Used when target implements interface.
- **CGLIB Proxy** – Used when no interface is implemented.
- **Note**: Proxying occurs at runtime, not compile-time.

---

#### 🔹 Spring AOP Limitations

- Only method execution join points supported.
- Self-invocation within same bean is **not** advised (no proxy involved).

---

#### 🔹 Common Use Cases

- Logging method calls
- Transaction management
- Access control (security)
- Performance metrics
- Caching

---

#### 🔹 Key Annotations Summary

```java
@Aspect
@Component
@EnableAspectJAutoProxy

@Before("pointcutExpression")
@After("pointcutExpression")
@AfterReturning("pointcutExpression")
@AfterThrowing("pointcutExpression")
@Around("pointcutExpression")
```

#### Spring AOP: Proxies and AspectJ Configuration

##### 🔹 1. **JDK Dynamic Proxies**

- **Interface-based**: Can only proxy **interfaces**.
- Spring uses this **by default** if your bean implements at least one interface.
- Created using the `java.lang.reflect.Proxy` API.

  ✅ **Example**:

  ```java
  public interface MyService {
      void doSomething();
  }

  @Service
  public class MyServiceImpl implements MyService {
      public void doSomething() {
          // ...
      }
  }
  ```

  ➡️ Spring will create a **JDK dynamic proxy** for `MyService`.

---

##### 🔹 2. **CGLIB Proxies**

- **Subclass-based**: Can proxy **concrete classes**, no interface required.
- Spring uses **CGLIB** when the bean doesn’t implement any interfaces **or** you force proxying the class.

  ✅ **Trigger CGLIB usage manually**:

  ```java
  @EnableAspectJAutoProxy(proxyTargetClass = true)
  ```

  ✅ CGLIB cannot proxy **final methods or final classes**.

---

##### 🔹 3. **AspectJ Proxies**

- Used when you're doing **compile-time** or **load-time weaving**.
- **More powerful** than proxies because it can:
  - Weave into **any method**, including `private` and `final` ones.
  - Add behavior without relying on Spring proxying rules.
- Requires AspectJ compiler (`ajc`) or **Load-Time Weaving (LTW)**.

  ✅ Not used by default in Spring Boot projects. You must configure it explicitly.

---

##### 🔹 Summary Table

| Proxy Type        | Requires Interface | Can Proxy Classes | Works with Final Methods | Used By Default |
|-------------------|--------------------|-------------------|---------------------------|------------------|
| JDK Dynamic Proxy | ✅ Yes              | ❌ No              | ❌ No                      | ✅ Yes (if interfaces exist) |
| CGLIB             | ❌ No               | ✅ Yes             | ❌ No                      | ✅ If no interfaces |
| AspectJ           | ❌ No               | ✅ Yes             | ✅ Yes                     | ❌ No             |

---

##### 🔹 Configuring AspectJ Auto Proxy in Spring

###### Basic Configuration

- Add the `@EnableAspectJAutoProxy` annotation in a `@Configuration` class:

  ```java
  @Configuration
  @EnableAspectJAutoProxy
  public class AppConfig {
      // your @Bean definitions
  }
  ```

  - This enables support for **@Aspect**-style annotations (`org.aspectj.lang.annotation`).

###### Optional: Force CGLIB Proxies (Class-Based)

- By default, Spring uses **JDK dynamic proxies** when possible.
- To force **CGLIB proxying**, even when an interface is present, use:

  ```java
  @Configuration
  @EnableAspectJAutoProxy(proxyTargetClass = true)
  public class AppConfig {
  }
  ```

  - Useful when the class doesn’t implement an interface or if you want class-based proxying.

###### What This Does

- Tells Spring to:
  - Scan for `@Aspect`-annotated classes.
  - Create proxies around beans as needed to apply advice from those aspects.

###### Typical Aspect Class Example

- Here's how to define an aspect:

  ```java
  @Aspect
  @Component
  public class LoggingAspect {
  
      @Before("execution(* com.example.service.*.*(..))")
      public void logBeforeMethod(JoinPoint joinPoint) {
          System.out.println("Before method: " + joinPoint.getSignature().getName());
      }
  }

  ```

  - The aspect class must be a Spring-managed bean (use `@Component` or register via `@Bean`).

###### If You're Using XML Instead of Java Config

- In XML-based Spring configuration:

  ```xml
  <aop:aspectj-autoproxy />
  ```

- Optional: Force CGLIB:

  ```xml
  <aop:aspectj-autoproxy proxy-target-class="true" />
  ```

###### Exam Pro Tip

- Spring AOP uses **proxies** (JDK or CGLIB), not full AspectJ weaving.
- **Full AspectJ weaving** (compile/load-time weaving) is not typical for Spring applications and is **not expected in-depth** for the certification.

### 💸 Spring Transaction Management (AOP)

---

#### 🔹 What is Transaction Management?

- Ensures **data consistency** in applications using **ACID** principles.
- Spring provides **declarative** and **programmatic** transaction management.
- **Declarative (AOP-based)** is preferred and common in Spring apps.

---

#### 🔹 Key Dependency (Spring Data / Tx)

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```

Or explicitly:

```xml
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-tx</artifactId>
</dependency>
```

---

#### 🔹 Core Annotation: `@Transactional`

- Used on **class** or **method** level.
- Spring creates **AOP proxy** to manage transactions.

```java
@Service
public class MyService {

    @Transactional
    public void performDbOperation() {
        // begin transaction
        // DB logic here
        // commit or rollback on exception
    }
}
```

---

#### 🔹 How It Works (AOP)

- Uses **proxy-based AOP** (JDK dynamic or CGLIB).
- Intercepts calls to `@Transactional` methods.
- Rolls back transaction on **unchecked exceptions** (`RuntimeException`, `Error`).

---

#### 🔹 Propagation Types (TX Propagation)

| Type                 | Behavior                                                                 |
|----------------------|--------------------------------------------------------------------------|
| `REQUIRED` (default) | Join existing or create new if none                                     |
| `REQUIRES_NEW`       | Suspends existing, always creates new                                   |
| `NESTED`             | Executes within nested transaction (if supported by DB)                 |
| `MANDATORY`          | Must run within existing transaction or throw exception                 |
| `SUPPORTS`           | Join existing if present; else run non-transactional                    |
| `NOT_SUPPORTED`      | Suspends transaction; runs without                                      |
| `NEVER`              | Fails if a transaction is active                                        |

Example:

```java
@Transactional(propagation = Propagation.REQUIRES_NEW)
public void createLogEntry() {
    // runs in its own transaction
}
```

---

#### 🔹 Rollback Rules

- By default, Spring only rolls back on **unchecked exceptions**.
- To roll back on **checked exceptions**, specify explicitly:

```java
@Transactional(rollbackFor = SQLException.class)
public void riskyOperation() throws SQLException {
    // will rollback on SQLException
}
```

---

#### 🔹 Read-Only Transactions

- Optimizes performance for **read-only operations**.

```java
@Transactional(readOnly = true)
public List<User> getAllUsers() {
    return userRepository.findAll();
}
```

- May give hints to DB (e.g., skip locking).

---

#### 🔹 Transaction Isolation Levels

| Level              | Dirty Read | Non-repeatable Read | Phantom Read | Description                                 |
|--------------------|------------|----------------------|--------------|---------------------------------------------|
| DEFAULT            | ❌         | ❌                   | ❌           | Uses the database's default settings       |
| READ_UNCOMMITTED   | ✅         | ✅                   | ✅           | Can read uncommitted changes               |
| READ_COMMITTED     | ❌         | ✅                   | ✅           | Can't read uncommitted changes             |
| REPEATABLE_READ    | ❌         | ❌                   | ✅           | Prevents dirty and non-repeatable reads    |
| SERIALIZABLE       | ❌         | ❌                   | ❌           | Full isolation; may slow down performance  |

```java
@Transactional(isolation = Isolation.REPEATABLE_READ)
```

---

#### 🔹 Self-Invocation Problem in Transactions

- Just like AOP, **self-invocation bypasses proxy**, so `@Transactional` won't work.

```java
@Transactional
public void outerMethod() {
    innerMethod(); // ❌ No TX management here
}

@Transactional
public void innerMethod() {
    // won't trigger TX
}
```

✅ **Fix**: Call from another bean or use `AopContext` to get proxy.

---

#### 🔹 Combining AOP and @Transactional

- Transaction management is **built on AOP**.
- `@Transactional` applies around advice via Spring proxy.
- Works **only on public methods** by default.

---

#### 🔹 Testing Transactions

- Spring test framework rolls back DB changes after test by default.

```java
@SpringBootTest
@Transactional
public class MyRepositoryTests {
    // DB changes rollback after each test
}
```

---

#### 🔹 Transaction Manager

- Responsible for managing transaction lifecycle (start, commit, rollback).
- Implements `PlatformTransactionManager` interface.
- Common implementations:
  - `DataSourceTransactionManager` (for JDBC)
  - `JpaTransactionManager` (for JPA)
  - `HibernateTransactionManager` (for Hibernate)
- Supports declarative and programmatic transaction management.

---

#### 🔹 Transaction Template

- A utility class to simplify programmatic transaction management.
- Wraps transactional code and reduces boilerplate.
- Uses `PlatformTransactionManager` under the hood.
- Example usage:

  ```java
  TransactionTemplate template = new TransactionTemplate(transactionManager);
  template.execute(status -> {
      // Transactional code
      return null;
  });

---

#### 🔹 Other Attributes

**timeout**: Defines the maximum time (in seconds) that a transaction can run before it is rolled back automatically.

**readOnly**: Indicates whether the transaction is read-only. When set to true, it can optimize the transaction and may prevent accidental changes to the database.

- true: Transaction is read-only.
- false (default): Transaction is read-write.

**rollbackFor**: Specifies which exceptions should cause the transaction to roll back.

- It accepts an array of exception classes. If any of these exceptions are thrown, the transaction will be rolled back.

**noRollbackFor**: Specifies which exceptions should not cause the transaction to roll back, even if they are thrown during the method execution.

---

#### ✅ Best Practices - Transactions

- Use `@Transactional` on **service layer**, not DAO/controller.
- Avoid using on **private/protected** methods.
- Avoid placing it on `@Scheduled` or async tasks (they bypass proxies).
- Handle **rollbackFor** carefully for checked exceptions.
- Split long TXs to avoid locks or performance issues.

---

#### 🧠 Summary Table

| Feature                   | Default / Notes                                    |
|---------------------------|----------------------------------------------------|
| Rollback on               | Unchecked exceptions only                          |
| Works with                | Public methods via proxies                         |
| Isolation level default   | `DEFAULT` (uses DB default)                        |
| Propagation default       | `REQUIRED`                                         |
| Read-only optimization    | `readOnly=true` for selects                        |
| Proxy required            | Yes (self-invocation won't work)                   |
| Testing behavior          | Auto rollback with `@Transactional`               |

---

🎯 **Exam Tip**: Expect questions on propagation, rollback rules, and self-invocation edge cases.

### Spring Security

#### 🔐 Core Concepts

- Spring Security is a powerful and customizable authentication and access-control framework.
- It is the standard for securing Spring-based applications.
- Operates through a filter chain that intercepts requests.

#### 🔑 Authentication

- **AuthenticationManager**: Main interface for authentication.
- **UsernamePasswordAuthenticationToken**: Used to pass user credentials.
- **UserDetailsService**: Loads user-specific data.
- **UserDetails**: Encapsulates user info (username, password, roles).
- Can be customized or used with in-memory, JDBC, or LDAP sources.

#### 🛡️ Authorization

- Role-based access control using `hasRole()`, `hasAuthority()`, `hasAnyRole()`, etc.
- Uses **AccessDecisionManager** and **AccessDecisionVoter** under the hood.
- **SecurityExpressionRoot**: Provides SpEL expressions like `isAuthenticated()`, `hasRole()`, etc.

#### 🧩 Configuration

- Uses **SecurityFilterChain** in Spring Security 6+.
- Configured using Java Config:

  ```java
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated())
        .formLogin(withDefaults());
      return http.build();
  }
  ```

- `WebSecurityCustomizer` used for excluding resources like static files:

  ```java
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
      return (web) -> web.ignoring().requestMatchers("/css/**", "/js/**");
  }
  ```

#### 📛 Annotation-Based Security

- Enable annotation support:

  ```java
  @EnableMethodSecurity // or @EnableGlobalMethodSecurity in older versions
  public class SecurityConfig { }
  ```

- Method-level security annotations:
  - `@PreAuthorize("hasRole('ADMIN')")`
  - `@PostAuthorize("returnObject.owner == authentication.name")`
  - `@Secured("ROLE_USER")` (Spring-style)
  - `@RolesAllowed("ROLE_USER")` (JSR-250 style; requires `@EnableMethodSecurity(jsr250Enabled = true)`)

- Example:

  ```java
  @PreAuthorize("hasRole('ADMIN')")
  public void deleteUser(Long userId) { ... }

  @PostAuthorize("returnObject.username == authentication.name")
  public User getUserDetails(Long id) { ... }

  @Secured({"ROLE_MANAGER", "ROLE_ADMIN"})
  public void approveRequest() { ... }
  ```

- Use SpEL expressions: `hasRole()`, `hasAuthority()`, `isAuthenticated()`, `principal.username`, etc.

#### 📜 JSR-250 Annotations in Spring Security

##### ✅ What is JSR-250?

- JSR-250 = Java Specification Request 250
- Defines standard annotations for role-based access control
- Aimed at unifying annotations across Java EE and compatible frameworks

##### 🔐 Common Annotations

- `@RolesAllowed("ROLE_NAME")` — Allows access only to specified roles
- `@PermitAll` — Grants access to everyone (authenticated or not)
- `@DenyAll` — Denies access to everyone

##### ⚙️ Enabling JSR-250 in Spring Security

- Must explicitly enable it in your configuration:

  ```java
  @EnableMethodSecurity(jsr250Enabled = true)
  @Configuration
  public class SecurityConfig { }
  ```

##### 🧠 Example Usage

```java
@RolesAllowed("ROLE_ADMIN")
public void deleteUser(Long id) { ... }

@PermitAll
public String homepage() { return "Welcome"; }

@DenyAll
public void restrictedMethod() { ... }
```

##### 🔄 Comparison with Other Annotations

| Annotation     | Type             | SpEL Support | Requires `ROLE_` Prefix | Notes                      |
|----------------|------------------|--------------|--------------------------|-----------------------------|
| `@RolesAllowed`| JSR-250          | ❌           | ✅ Yes                   | Standardized                |
| `@Secured`     | Spring-specific  | ❌           | ✅ Yes                   | Similar to `@RolesAllowed` |
| `@PreAuthorize`| Spring Security  | ✅ Yes       | ❌ Optional              | Most powerful, uses SpEL    |

##### 📌 Notes

- JSR-250 annotations are **method-level** only.
- `@RolesAllowed` must use the full role name, e.g., `"ROLE_ADMIN"`.
- JSR-250 annotations are simple and readable but not as flexible as SpEL-based ones like `@PreAuthorize`.

#### 🔄 Security Filters

- Built on a **chain of filters**, e.g. `UsernamePasswordAuthenticationFilter`, `BasicAuthenticationFilter`, etc.
- Filters are automatically registered via `FilterChainProxy`.
- Custom filters can be added with `http.addFilterBefore()` or `http.addFilterAfter()`.

#### 🔄 Session Management

- Configurable session handling:
  - `sessionManagement().sessionCreationPolicy(...)`
  - Options: `ALWAYS`, `NEVER`, `IF_REQUIRED`, `STATELESS`
- Protection against session fixation via `.sessionFixation().migrateSession()`

#### 🔐 CSRF Protection

- Enabled by default for state-changing operations (e.g. POST, PUT).
- Can be disabled with `.csrf().disable()` for stateless APIs.
- Token included as hidden form input or request header (`X-CSRF-TOKEN`).

#### 🔏 Password Encoding

- Use **PasswordEncoder** (e.g., `BCryptPasswordEncoder`) for secure password hashing.
- No plain-text passwords.

  ```java
  @Bean
  public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
  }
  ```

#### 🌍 OAuth2 and JWT

- Support for OAuth2 Login and Resource Server.
- `spring-boot-starter-oauth2-client` and `spring-boot-starter-oauth2-resource-server`.
- OAuth2 client configuration in `application.properties` or `application.yml`.
- JWT parsing and verification handled via `NimbusJwtDecoder`.

#### 🧪 Testing with Spring Security

- Use `@WithMockUser` for unit tests.
- Use `SecurityMockMvcRequestPostProcessors` for custom user roles in MVC tests.
- Test annotations:
  - `@WithMockUser`
  - `@WithUserDetails`

#### 🧰 Miscellaneous

- Remember Me functionality with `rememberMe()`.
- HTTP Basic Auth with `http.httpBasic()`.
- HTTPS enforcement with `requiresChannel().anyRequest().requiresSecure()`.
- CORS configuration via `cors()` and `CorsConfigurationSource`.

#### 📚 Best Practices

- Always hash passwords.
- Minimize use of `.permitAll()` unless explicitly required.
- Prefer method-level security for finer control.
- Keep security configuration readable and modular.

#### MVC Matchers in Spring Security

- **Purpose:** Used to configure security for specific URL patterns in Spring Security.
- **Syntax:**
  - `http.authorizeRequests().mvcMatchers("/path").permitAll();`
  - Allows specifying security rules for URL patterns using Spring MVC-style matchers.
  
- **Common Use Cases:**
  - **Configuring access to URLs:**

    ```java
    http.authorizeRequests()
        .mvcMatchers("/home", "/about").permitAll()
        .mvcMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated();
    ```

    - `/home` and `/about` are open to all.
    - `/admin/**` is restricted to users with the `ADMIN` role.

- **Advanced Configuration:**
  - Can combine `mvcMatchers` with other methods like `hasRole`, `permitAll`, `authenticated`, etc.
  - **Example:** Allow access to specific URLs and apply role-based restrictions to others.

    ```java
    http.authorizeRequests()
        .mvcMatchers("/public/**").permitAll()
        .mvcMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated();
    ```

---

#### ANT Matchers in Spring Security

- **Purpose:** Used to define URL patterns with wildcards for access control in Spring Security.
- **Syntax:**
  - `http.authorizeRequests().antMatchers("/path/**").permitAll();`
  - The `antMatchers()` method uses ANT-style path patterns with wildcards (`*`, `**`).
  
- **Common Use Cases:**
  - **ANT Wildcards:**
    - `*` matches any part of a path (e.g., `/home/*` matches `/home/page1`).
    - `**` matches any nested path (e.g., `/admin/**` matches `/admin/user/profile`).
  - **Example:**

    ```java
    http.authorizeRequests()
        .antMatchers("/public/**").permitAll()
        .antMatchers("/user/**").hasRole("USER")
        .anyRequest().authenticated();
    ```

    - `/public/**` is open to all, `/user/**` is restricted to `USER` role, and other paths require authentication.

- **Advanced Configuration:**
  - `antMatchers` allows for complex patterns, such as excluding specific files or matching nested URLs.

    ```java
    http.authorizeRequests()
        .antMatchers("/api/**").hasRole("API_USER")
        .antMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated();
    ```

---

#### Request Matchers in Spring Security

- **Purpose:** Used to match HTTP requests in Spring Security, often to define custom security rules for specific HTTP methods or paths.
- **Syntax:**
  - `http.authorizeRequests().requestMatchers("/path").permitAll();`
  - `requestMatchers()` can be used with path patterns, methods (`GET`, `POST`, etc.), or even `HttpMethod`.

- **Common Use Cases:**
  - **Path and Method Matching:**

    ```java
    http.authorizeRequests()
        .requestMatchers(HttpMethod.GET, "/public/**").permitAll()
        .requestMatchers(HttpMethod.POST, "/login").permitAll()
        .anyRequest().authenticated();
    ```

    - Matches `GET` requests to `/public/**` and `POST` requests to `/login`, permitting access.
  
  - **Multiple Request Matchers:**

    ```java
    http.authorizeRequests()
        .requestMatchers("/admin/**", "/dashboard/**").hasRole("ADMIN")
        .requestMatchers("/public/**").permitAll()
        .anyRequest().authenticated();
    ```

- **Advanced Configuration:**
  - **Combining Request Methods:** `requestMatchers()` allows combining methods for specific paths.

    ```java
    http.authorizeRequests()
        .requestMatchers(HttpMethod.GET, "/resources/**").permitAll()
        .requestMatchers(HttpMethod.POST, "/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated();

## Specific notes

### @Order

### @Order Annotation in Spring

- **Purpose:** Specifies the order in which beans are loaded or executed.
- **Syntax:** `@Order(value)`
  - `value`: Integer, lower value = higher priority.

- **Common Use Cases:**
  - **Filters:**

    ```java
    @Order(1)
    public class CustomFilter1 implements Filter { ... }

    @Order(2)
    public class CustomFilter2 implements Filter { ... }
    ```

  - **Event Listeners:**

    ```java
    @Component
    @Order(1)
    public class FirstListener implements ApplicationListener<ApplicationEvent> { ... }
    ```

  - **Configuration Classes:**

    ```java
    @Configuration
    @Order(1)
    public class ConfigClassOne { ... }
    ```

  - **AOP Aspects:**

    ```java
    @Aspect
    @Order(1)
    public class LoggingAspect { ... }
    ```

- **Priority:**
  - Lower values = higher priority.
  - **`Ordered.HIGHEST_PRECEDENCE`**: `Integer.MIN_VALUE` (first to execute).
  - **`Ordered.LOWEST_PRECEDENCE`**: `Integer.MAX_VALUE` (last to execute).

- **Spring’s Ordered Interface:**
  - Use `Ordered` interface if you prefer not to use `@Order`.

  ```java
  public class MyBean implements Ordered {
      @Override
      public int getOrder() {
          return 1; // Lower values = higher priority
      }
  }

### @Conditional

### @Conditional Annotation in Spring

- **Purpose:** Used to conditionally register a bean in the Spring context based on certain conditions.
- **Syntax:** `@Conditional(SomeCondition.class)`
  - `SomeCondition.class`: The condition class that determines if the bean should be registered.

- **Common Use Cases:**
  - **Conditional Beans:**

    ```java
    @Configuration
    public class Config {
        
        @Bean
        @Conditional(OnDevCondition.class)
        public DataSource devDataSource() {
            return new DataSource("dev-db-url");
        }
        
        @Bean
        @Conditional(OnProdCondition.class)
        public DataSource prodDataSource() {
            return new DataSource("prod-db-url");
        }
    }
    ```

    In this example, `devDataSource` is only registered if `OnDevCondition` is true, and `prodDataSource` is only registered if `OnProdCondition` is true.

- **Creating Custom Conditions:**
  - **`Condition` Interface:** To create a custom condition, implement the `Condition` interface and override `matches()` method.

  ```java
  public class OnDevCondition implements Condition {
      @Override
      public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
          return "dev".equals(System.getProperty("env"));
      }
  }

### Spring bean life cycle

  ![Spring Bean Life Cycle](image.png)

### DispatcherServlet and Everything Around It

- **Purpose:**
  - The **DispatcherServlet** is the front controller in Spring MVC, handling all HTTP requests and delegating them to the appropriate components like controllers, view resolvers, etc.

- **DispatcherServlet Workflow:**
  1. **Request Handling:** The `DispatcherServlet` intercepts all incoming requests.
  2. **Handler Mapping:** It determines which controller method should handle the request based on URL patterns.
  3. **Controller Execution:** The matched controller method is executed, and it returns a `ModelAndView` (or `ResponseEntity` in case of REST).
  4. **View Resolution:** The `DispatcherServlet` delegates to the appropriate `ViewResolver` to resolve the view (e.g., JSP, Thymeleaf).
  5. **Response Rendering:** The view is rendered and the response is sent to the client.

- **DispatcherServlet Configuration:**
  - Typically defined in `web.xml` or using Java config in `@Configuration` classes.
  - **web.xml Example:**

    ```xml
    <servlet>
        <servlet-name>dispatcher</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <load-on-startup>1</load-on-startup>
    </servlet>
    <servlet-mapping>
        <servlet-name>dispatcher</servlet-name>
        <url-pattern>/</url-pattern>
    </servlet-mapping>
    ```

- **DispatcherServlet Components:**
  1. **HandlerMapping:** Maps HTTP requests to controller methods.
     - **Example:** `RequestMappingHandlerMapping` is the default handler mapping in Spring MVC.
  2. **HandlerAdapter:** Invokes the controller method that was mapped by `HandlerMapping`.
     - **Example:** `RequestMappingHandlerAdapter` is the default adapter.
  3. **ViewResolver:** Resolves logical view names to physical views.
  4. **ExceptionResolver:** Handles any exceptions thrown during request processing.
     - **Example:** `SimpleMappingExceptionResolver` maps exceptions to error views.

- **DispatcherServlet's Role in REST:**
  - In REST APIs, `DispatcherServlet` routes requests to `@RestController` methods, typically returning data as JSON or XML rather than rendering a view.
  - Example:

    ```java
    @RestController
    public class ApiController {
        @GetMapping("/api/message")
        public String getMessage() {
            return "Hello from REST!";
        }
    }
    ```

---

### Spring View Resolvers and Model Views

- **Purpose:**
  - View resolvers in Spring are used to map a logical view name to an actual view, such as a JSP, Thymeleaf template, or other types of views.
  - **ModelAndView** is used to store the view name and model data to be rendered.

- **View Resolver Types:**
  1. **InternalResourceViewResolver (JSP, HTML)**
     - Resolves view names to internal resources like JSP files.
     - **Syntax:**

       ```java
       @Bean
       public InternalResourceViewResolver viewResolver() {
           InternalResourceViewResolver resolver = new InternalResourceViewResolver();
           resolver.setPrefix("/WEB-INF/views/");
           resolver.setSuffix(".jsp");
           return resolver;
       }
       ```

     - Maps a logical view name to a physical JSP file (e.g., `"home"` -> `/WEB-INF/views/home.jsp`).
  
  2. **ThymeleafViewResolver (Thymeleaf)**
     - Resolves view names to Thymeleaf templates.
     - **Syntax:**

       ```java
       @Bean
       public SpringTemplateEngine templateEngine() {
           SpringTemplateEngine templateEngine = new SpringTemplateEngine();
           templateEngine.setTemplateResolver(templateResolver());
           return templateEngine();
       }
  
       @Bean
       public ThymeleafViewResolver viewResolver() {
           ThymeleafViewResolver resolver = new ThymeleafViewResolver();
           resolver.setTemplateEngine(templateEngine());
           return resolver;
       }
       ```
  
  3. **FreeMarkerViewResolver (FreeMarker)**
     - Resolves view names to FreeMarker templates.
     - **Syntax:**

       ```java
       @Bean
       public FreeMarkerViewResolver viewResolver() {
           FreeMarkerViewResolver resolver = new FreeMarkerViewResolver();
           resolver.setSuffix(".ftl");
           resolver.setPrefix("/WEB-INF/views/");
           return resolver;
       }
       ```

- **ModelAndView:**
  - Used to combine both the model data and view in a single return object.
  - **Syntax:**

    ```java
    @RequestMapping("/home")
    public ModelAndView home() {
        ModelAndView modelAndView = new ModelAndView("home");
        modelAndView.addObject("message", "Welcome to Spring MVC!");
        return modelAndView;
    }
    ```

- **View Resolver Workflow:**
  1. The controller returns a logical view name (e.g., `"home"`).
  2. The view resolver maps this name to a physical resource (e.g., `/WEB-INF/views/home.jsp`).
  3. The view is rendered with data from the model.

---

#### Summary Points for Exam

- **DispatcherServlet:**
  - **Purpose:** Front controller that routes requests to appropriate handlers (controllers, view resolvers, etc.).
  - **Workflow:** Manages request processing, including handler mapping, view resolution, and rendering.
  - **Components:** `HandlerMapping`, `HandlerAdapter`, `ViewResolver`, `ExceptionResolver`.
  
- **View Resolvers:**
  - **Purpose:** Maps logical view names to physical views (JSP, Thymeleaf, FreeMarker).
  - **Common Types:** `InternalResourceViewResolver`, `ThymeleafViewResolver`, `FreeMarkerViewResolver`.
  - **ModelAndView:** Used to return both model data and the view name from controllers.
  
- **URL Mapping:** Handled via annotations like `@RequestMapping` or `@GetMapping` to map specific paths to controller methods.

### REST Status Codes

- **Purpose:** REST status codes indicate the outcome of an HTTP request. They are part of the HTTP response, providing context about the request's success or failure.
  
- **Common Categories:**
  1. **2xx (Successful)**
     - `200 OK`: Request succeeded.
     - `201 Created`: Resource successfully created.
     - `204 No Content`: Request succeeded but no content to return.
  
  2. **3xx (Redirection)**
     - `301 Moved Permanently`: Resource has been permanently moved.
     - `302 Found`: Resource has been temporarily moved.
  
  3. **4xx (Client Error)**
     - `400 Bad Request`: Invalid request.
     - `401 Unauthorized`: Authentication required.
     - `403 Forbidden`: Server refuses to authorize the request.
     - `404 Not Found`: Resource not found.
  
  4. **5xx (Server Error)**
     - `500 Internal Server Error`: General server error.
     - `502 Bad Gateway`: Server acting as a gateway received an invalid response.
     - `503 Service Unavailable`: Server is currently unavailable.

---

### Callback Interfaces with JDBC Template

- **Purpose:** Callback interfaces are used to abstract common operations such as connection setup, execution, and resource cleanup with JDBC in Spring.

- **Common Callback Interfaces:**
  1. **ResultSetExtractor:** Used for extracting results from a `ResultSet` object.
     - **Example:**

       ```java
       public class MyResultSetExtractor implements ResultSetExtractor<List<MyEntity>> {
           @Override
           public List<MyEntity> extractData(ResultSet rs) throws SQLException, DataAccessException {
               List<MyEntity> list = new ArrayList<>();
               while (rs.next()) {
                   MyEntity entity = new MyEntity(rs.getInt("id"), rs.getString("name"));
                   list.add(entity);
               }
               return list;
           }
       }
       ```

  2. **RowMapper:** Used to map each row of a `ResultSet` to an entity.
     - **Example:**

       ```java
       public class MyRowMapper implements RowMapper<MyEntity> {
           @Override
           public MyEntity mapRow(ResultSet rs, int rowNum) throws SQLException {
               return new MyEntity(rs.getInt("id"), rs.getString("name"));
           }
       }
       ```

  3. **PreparedStatementSetter:** Used to set values in `PreparedStatement` before execution.
     - **Example:**

       ```java
       public class MyPreparedStatementSetter implements PreparedStatementSetter {
           @Override
           public void setValues(PreparedStatement ps) throws SQLException {
               ps.setInt(1, 10);
           }
       }
       ```

---

### Idempotent HTTP Methods

- **Definition:** HTTP methods that can be repeated multiple times with the same effect as if they were executed once.
  
- **Examples:**
  - `GET`: Retrieving the same resource multiple times doesn’t change the resource.
  - `PUT`: Updating a resource with the same data doesn’t change its state.
  - `DELETE`: Deleting a resource multiple times doesn’t have any effect after the first deletion.

### Request mapping arguments

- **value** (String[]):
  - Specifies the URI path that the method will handle.
  
- **method** (RequestMethod[]):
  - Specifies the HTTP method(s) (e.g., GET, POST, PUT, DELETE) for the request mapping.
  
- **params** (String[]):
  - Specifies the request parameters that must be present for the mapping to be invoked.
  
- **headers** (String[]):
  - Specifies the HTTP headers that must be present for the mapping to be invoked.
  
- **consumes** (String[]):
  - Specifies the media types that the method can consume (e.g., `application/json`, `application/xml`).
  
- **produces** (String[]):
  - Specifies the media types that the method can produce as a response (e.g., `application/json`, `application/xml`).
  
- **name** (String):
  - Allows you to specify the name of the handler method.

- **params** (String[]):
  - Conditions for the request parameters to match for the method to be invoked.
  
- **headers** (String[]):
  - Conditions for the request headers to match for the method to be invoked.

### Supported Controller Method Arguments in Spring

- **`@RequestParam`**
  - Binds a web request parameter to a method parameter.
  - Example: `@RequestParam("id") Long id`
  - Can be required or optional (`required = false`).

- **`@PathVariable`**
  - Binds a URI template variable to a method parameter.
  - Example: `@GetMapping("/users/{id}") public User getUser(@PathVariable Long id)`

- **`@RequestBody`**
  - Binds the HTTP request body to a method parameter (typically for POST or PUT requests).
  - Example: `@PostMapping("/users") public void addUser(@RequestBody User user)`

- **`@RequestHeader`**
  - Binds a request header to a method parameter.
  - Example: `@RequestHeader("Authorization") String authHeader`

- **`@CookieValue`**
  - Binds a cookie value to a method parameter.
  - Example: `@CookieValue("SESSIONID") String sessionId`

- **`@ModelAttribute`**
  - Binds request parameters to a model object (typically used for form submissions).
  - Example: `@PostMapping("/submitForm") public String submit(@ModelAttribute User user)`

- **`@RequestPart`**
  - Binds a part of a multipart request to a method parameter (typically used for file uploads).
  - Example: `@PostMapping("/upload") public void uploadFile(@RequestPart("file") MultipartFile file)`

- **`Principal` (from `java.security.Principal`)**
  - Provides the authenticated user’s principal (name) in a secured application.
  - Example: `public String getUsername(Principal principal)`

- **`HttpServletRequest`**
  - Provides access to the raw HTTP request.
  - Example: `public String handleRequest(HttpServletRequest request)`

- **`HttpServletResponse`**
  - Provides access to the raw HTTP response.
  - Example: `public void handleResponse(HttpServletResponse response)`

- **`@RequestMapping` method parameters**
  - Supports additional custom arguments like `HttpEntity`, `ResponseEntity`, etc.
  - Example: `public ResponseEntity<String> handleResponse(HttpEntity<String> entity)`

- **`@SessionAttribute`**
  - Binds a session attribute to a method parameter.
  - Example: `public String handleSession(@SessionAttribute("user") User user)`

- **`@Value`**
  - Used for injecting values from application properties or environment variables.
  - Example: `@Value("${app.name}") private String appName`

- **`jakarta.servlet.http.HttpSession`**
  - Enforces the presence of a session and is never null.
  - Accessing the session directly is not thread-safe. If concurrent access is needed, set `synchronizeOnSession` flag to true on `RequestMappingHandlerAdapter`.
  - Example: `public String getSession(HttpSession session)`

- **`java.util.Locale`**
  - The current request locale, determined by the most specific `LocaleResolver` available.
  - Example: `public String handleLocale(Locale locale)`

- **`java.security.Principal`**
  - Represents the currently authenticated user. May be a specific `Principal` implementation.
  - Example: `public String handlePrincipal(Principal principal)`
