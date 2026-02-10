package io.github.libxposed.helper;

import android.os.Build;
import android.os.Handler;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.RequiresOptIn;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import dalvik.system.BaseDexClassLoader;
import io.github.libxposed.api.XposedInterface;

/**
 * A powerful hook builder for Xposed modules that provides a fluent API for matching and hooking
 * Android framework classes, methods, fields, and constructors.
 *
 * <p>This interface supports advanced matching capabilities including:
 * <ul>
 *   <li>Reflection-based matching (class names, method signatures, field types, etc.)</li>
 *   <li>DEX bytecode analysis (opcodes, invoked methods, referenced strings, etc.)</li>
 *   <li>Annotation-based matching</li>
 *   <li>Caching for improved performance</li>
 *   <li>Asynchronous hook building with callbacks</li>
 * </ul>
 *
 * <p>Basic example:
 * <pre>{@code
 * public class MyModule extends XposedModule {
 *     public MyModule(XposedInterface base, ModuleLoadedParam param) {
 *         super(base, param);
 *     }
 *
 *     @Override
 *     public void onPackageLoaded(PackageLoadedParam param) {
 *         var future = HookBuilder.buildHooks(this, param.getClassLoader(),
 *                 param.getApplicationInfo().sourceDir, builder -> {
 *             builder.firstMethod(m -> m
 *                 .setDeclaringClass(builder.exactClass("android.app.Activity"))
 *                 .setName(builder.exact("onCreate"))
 *                 .setParameterCount(1)
 *             ).onMatch(method -> {
 *                 hook(method, ActivityHooker.class);
 *             });
 *         });
 *         try { future.get(); } catch (Exception e) { }
 *     }
 *
 *     public static class ActivityHooker implements Hooker {
 *         public static void before(BeforeHookCallback callback) {
 *             log("Activity.onCreate() called");
 *         }
 *     }
 * }
 * }</pre>
 *
 * <p>Advanced example with DEX analysis cache and configuration:
 * <pre>{@code
 * public class MyModule extends XposedModule {
 *     public MyModule(XposedInterface base, ModuleLoadedParam param) {
 *         super(base, param);
 *     }
 *
 *     @Override
 *     public void onPackageLoaded(PackageLoadedParam param) {
 *         ApplicationInfo appInfo = param.getApplicationInfo();
 *         File cacheDir = new File(appInfo.dataDir, "cache/libxposed");
 *         File cacheFile = new File(cacheDir, "parseDex.bin");
 *
 *         var future = HookBuilder.buildHooks(this, param.getClassLoader(),
 *                 appInfo.sourceDir, builder -> {
 *             if (cacheFile.exists()) {
 *                 try {
 *                     builder.setCacheInputStream(new FileInputStream(cacheFile));
 *                 } catch (IOException e) {
 *                     log("Failed to load cache", e);
 *                 }
 *             }
 *
 *             cacheDir.mkdirs();
 *             try {
 *                 builder.setCacheOutputStream(new FileOutputStream(cacheFile));
 *             } catch (IOException e) {
 *                 log("Failed to create cache output", e);
 *             }
 *
 *             // Configure async execution
 *             builder.setExecutorService(Executors.newFixedThreadPool(4));
 *
 *             // Configure callback handler (e.g., main thread)
 *             builder.setCallbackHandler(new Handler(Looper.getMainLooper()));
 *
 *             // Configure exception handler
 *             builder.setExceptionHandler(throwable -> {
 *                 log("Hook building error: " + throwable.getMessage(), throwable);
 *                 return true; // Suppress exception
 *             });
 *
 *             // Use DEX analysis to find methods
 *             builder.methods(m -> m
 *                 .setDeclaringClass(builder.exactClass("com.example.MainActivity"))
 *                 .setReferredStrings(builder.exact("secret_key").observe())
 *             ).onMatch(methods -> {
 *                 for (Method method : methods) {
 *                     hook(method, SecurityHooker.class);
 *                 }
 *             });
 *         });
 *         try { future.get(); } catch (Exception e) { }
 *     }
 * }
 * }</pre>
 *
 * @see #buildHooks(XposedInterface, BaseDexClassLoader, String, Consumer)
 */
@SuppressWarnings("unused")
public interface HookBuilder {

    /**
     * Builds hooks asynchronously based on the provided configuration.
     *
     * <p>This method creates a new HookBuilder instance, applies the consumer configuration,
     * and returns a Future that completes when all hooks have been processed.
     *
     * <p>Basic usage example:
     * <pre>{@code
     * @Override
     * public void onPackageLoaded(PackageLoadedParam param) {
     *     var future = HookBuilder.buildHooks(this, param.getClassLoader(),
     *             param.getApplicationInfo().sourceDir, builder -> {
     *         // Match and hook methods
     *         builder.firstMethod(m -> m
     *             .setDeclaringClass(builder.exactClass("com.example.MyClass"))
     *             .setName(builder.exact("targetMethod"))
     *         ).onMatch(method -> {
     *             hook(method, MyHooker.class);
     *         });
     *     });
     *     try { future.get(); } catch (Exception e) { }
     * }
     * }</pre>
     *
     * <p>Advanced usage with DEX analysis caching and full configuration:
     * <pre>{@code
     * @Override
     * public void onPackageLoaded(PackageLoadedParam param) {
     *     ApplicationInfo appInfo = param.getApplicationInfo();
     *     var cacheDir = new File(param.getApplicationInfo().dataDir, "cache/libxposed");
     *     // Binary cache produced via ObjectOutputStream (not JSON)
     *     File cacheFile = new File(cacheDir, "parseDex.bin");
     *
     *     Future<?> future = HookBuilder.buildHooks(this, param.getClassLoader(),
     *             appInfo.sourceDir, builder -> {
     *
     *         // 1. Setup cache input - read previously saved binary DEX analysis results
     *         if (cacheFile.exists()) {
     *             try {
     *                 builder.setCacheInputStream(new FileInputStream(cacheFile));
     *             } catch (IOException e) {
     *                 log("Cache read failed", e);
     *             }
     *         }
     *
     *         // 2. Setup cache output - save DEX analysis results for next time
     *         cacheFile.getParentFile().mkdirs();
     *         try {
     *             builder.setCacheOutputStream(new FileOutputStream(cacheFile));
     *         } catch (IOException e) {
     *             log("Cache write failed", e);
     *         }
     *
     *         // 3. Force fresh DEX analysis (useful for debugging)
     *         // builder.setForceDexAnalysis(true);
     *
     *         // 4. Configure thread pool for parallel processing (default: CPU cores)
     *         builder.setExecutorService(Executors.newFixedThreadPool(4));
     *
     *         // 5. Run match callbacks on specific thread (e.g., main thread)
     *         // builder.setCallbackHandler(new Handler(Looper.getMainLooper()));
     *
     *         // 6. Handle errors gracefully
     *         builder.setExceptionHandler(throwable -> {
     *             log("Hook error: " + throwable.getMessage(), throwable);
     *             return true; // return true to suppress exception
     *         });
     *
     *         // 7. Use DEX analysis to find methods by bytecode content
     *         builder.methods(m -> m
     *             .setDeclaringClass(builder.exactClass("com.example.auth.Auth"))
     *             // Find methods that reference these strings
     *             .setReferredStrings(
     *                 builder.exact("api_key").observe()
     *                     .or(builder.exact("secret_token").observe())
     *             )
     *             // Find methods that invoke Log.d
     *             .setInvokedMethods(
     *                 builder.exactMethod("android.util.Log->d(Ljava/lang/String;Ljava/lang/String;)I")
     *                     .observe()
     *             )
     *         ).onMatch(methods -> {
     *             log("Found " + methods.spliterator().estimateSize() + " methods");
     *             for (Method method : methods) {
     *                 hook(method, SecurityHooker.class);
     *             }
     *         });
     *     });
     *
     *     // Must call and wait for completion (blocks current thread)
     *     try { future.get(); } catch (Exception e) { }
     * }
     * }</pre>
     *
     * @param ctx the Xposed interface context for hook operations
     * @param classLoader the class loader to use for loading classes
     * @param sourcePath the path to the DEX file or APK to analyze
     * @param consumer a consumer that configures the hook builder with matchers and callbacks
     * @return a Future that completes when hook building is finished
     * @throws NullPointerException if any parameter is null
     */
    @NonNull
    static Future<?> buildHooks(@NonNull XposedInterface ctx, @NonNull BaseDexClassLoader classLoader, @NonNull String sourcePath, Consumer<HookBuilder> consumer) {
        var builder = new HookBuilderImpl(ctx, classLoader, sourcePath);
        consumer.accept(builder);
        return builder.build();
    }

    /**
     * Forces DEX bytecode analysis even if cached results are available.
     *
     * <p>This is useful for debugging or when you need to ensure fresh analysis results.
     * Note that DEX analysis can be time-consuming for large applications.
     *
     * @param forceDexAnalysis true to force fresh DEX analysis, false to use cached results
     * @return this builder for method chaining
     */
    @DexAnalysis
    @NonNull
    HookBuilder setForceDexAnalysis(boolean forceDexAnalysis);

    /**
     * Sets the executor service for asynchronous hook building operations.
     *
     * <p>By default, a suitable executor will be created automatically.
     * Use this method to provide a custom executor for better control over thread management.
     *
     * @param executorService the executor service to use for async operations
     * @return this builder for method chaining
     */
    @NonNull
    HookBuilder setExecutorService(@NonNull ExecutorService executorService);

    /**
     * Sets the handler for callbacks when hooks are matched.
     *
     * <p>All hook match callbacks will be posted to this handler's thread.
     * This is useful for ensuring callbacks run on a specific thread (e.g., main thread).
     *
     * @param callbackHandler the handler to use for posting callbacks
     * @return this builder for method chaining
     */
    @NonNull
    HookBuilder setCallbackHandler(@NonNull Handler callbackHandler);

    /**
     * Sets a predicate to validate cached analysis results.
     *
     * <p>The predicate receives the cacheInfo map (containing metadata about the cache)
     * and returns {@code true} if the cache should be used, or {@code false} to rebuild.
     *
     * <p><b>Default behavior (if not set):</b> The framework automatically checks if the
     * DEX file's {@code lastModifyTime} has changed. If the timestamp differs from the
     * cached value, the cache is invalidated and rebuilt. This handles most use cases
     * without requiring custom validation.
     *
     * <p>Example (optional custom validation):
     * <pre>{@code
     * builder.setCacheChecker(cacheInfo -> {
     *     // Add custom checks beyond lastModifyTime
     *     Object customData = cacheInfo.get("myCustomData");
     *     return customData != null && validateCustomData(customData);
     * });
     * }</pre>
     *
     * @param cacheChecker predicate that tests the cacheInfo map
     * @return this builder for method chaining
     */
    @NonNull
    HookBuilder setCacheChecker(@NonNull Predicate<Map<String, Object>> cacheChecker);

    /**
     * Sets an input stream to read cached analysis results.
     *
     * <p>This enables persistent caching of DEX analysis results across sessions,
     * significantly improving startup time for complex matching operations.
     *
     * <p><b>Note:</b> The builder takes ownership of the provided stream and will
     * automatically close it after reading the cache data. Callers should not close
     * the stream themselves.
     *
     * @param cacheInputStream the input stream to read cache data from
     * @return this builder for method chaining
     */
    @NonNull
    HookBuilder setCacheInputStream(@NonNull InputStream cacheInputStream);

    /**
     * Sets an output stream to write analysis results for caching.
     *
     * <p>The analysis cache will be written to this stream when hook building completes,
     * allowing it to be reused in future sessions.
     *
     * <p><b>Note:</b> The builder takes ownership of the provided stream and will
     * automatically close it after writing the cache data. Callers should not close
     * the stream themselves.
     *
     * @param cacheOutputStream the output stream to write cache data to
     * @return this builder for method chaining
     */
    @NonNull
    HookBuilder setCacheOutputStream(@NonNull OutputStream cacheOutputStream);

    /**
     * Sets an exception handler for errors during hook building.
     *
     * <p>The handler receives exceptions that occur during matching or hooking
     * and returns true if the exception was handled (suppressed), or false to rethrow it.
     *
     * @param handler predicate that handles exceptions
     * @return this builder for method chaining
     */
    @NonNull
    HookBuilder setExceptionHandler(@NonNull Predicate<Throwable> handler);

    /**
     * Creates a lazy sequence of methods matching the specified criteria.
     *
     * <p>The matcher will find all methods that satisfy the conditions configured
     * in the consumer. Results are evaluated lazily.
     *
     * @param matcher consumer that configures the method matching criteria
     * @return a lazy sequence of matching methods
     */
    @NonNull
    MethodLazySequence methods(@NonNull Consumer<MethodMatcher> matcher);

    /**
     * Finds the first method matching the specified criteria.
     *
     * <p>This is more efficient than {@link #methods(Consumer)} when you only need
     * one match, as it stops searching after finding the first match.
     *
     * @param matcher consumer that configures the method matching criteria
     * @return a match object for the first matching method
     */
    @NonNull
    MethodMatch firstMethod(@NonNull Consumer<MethodMatcher> matcher);

    /**
     * Creates a lazy sequence of constructors matching the specified criteria.
     *
     * @param matcher consumer that configures the constructor matching criteria
     * @return a lazy sequence of matching constructors
     */
    @NonNull
    ConstructorLazySequence constructors(@NonNull Consumer<ConstructorMatcher> matcher);

    /**
     * Finds the first constructor matching the specified criteria.
     *
     * @param matcher consumer that configures the constructor matching criteria
     * @return a match object for the first matching constructor
     */
    @NonNull
    ConstructorMatch firstConstructor(@NonNull Consumer<ConstructorMatcher> matcher);

    /**
     * Creates a lazy sequence of fields matching the specified criteria.
     *
     * @param matcher consumer that configures the field matching criteria
     * @return a lazy sequence of matching fields
     */
    @NonNull
    FieldLazySequence fields(@NonNull Consumer<FieldMatcher> matcher);

    /**
     * Finds the first field matching the specified criteria.
     *
     * @param matcher consumer that configures the field matching criteria
     * @return a match object for the first matching field
     */
    @NonNull
    FieldMatch firstField(@NonNull Consumer<FieldMatcher> matcher);

    /**
     * Creates a lazy sequence of classes matching the specified criteria.
     *
     * @param matcher consumer that configures the class matching criteria
     * @return a lazy sequence of matching classes
     */
    @NonNull
    ClassLazySequence classes(@NonNull Consumer<ClassMatcher> matcher);

    /**
     * Finds the first class matching the specified criteria.
     *
     * @param matcher consumer that configures the class matching criteria
     * @return a match object for the first matching class
     */
    @NonNull
    ClassMatch firstClass(@NonNull Consumer<ClassMatcher> matcher);

    /**
     * Creates a string match for an exact string value.
     *
     * @param string the exact string to match
     * @return a string match object
     */
    @NonNull
    StringMatch exact(@NonNull String string);

    /**
     * Creates a string match for strings starting with the specified prefix.
     *
     * @param prefix the prefix that strings must start with
     * @return a string match object
     */
    @NonNull
    StringMatch prefix(@NonNull String prefix);

    /**
     * Finds the first string starting with the specified prefix.
     *
     * @param prefix the prefix that the string must start with
     * @return a string match object for the first matching string
     */
    @NonNull
    StringMatch firstPrefix(@NonNull String prefix);

    /**
     * Finds a class by its exact fully qualified name.
     *
     * @param name the fully qualified class name (e.g., "android.app.Activity")
     * @return a class match object
     */
    @NonNull
    ClassMatch exactClass(@NonNull String name);

    /**
     * Creates a match for the specified class object.
     *
     * @param clazz the class to match
     * @return a class match object
     */
    @NonNull
    ClassMatch exact(@NonNull Class<?> clazz);

    /**
     * Finds a method by its exact signature.
     *
     * <p>The signature format is: "className->methodName(paramTypes)returnType"
     * where paramTypes and returnType are in Smali format.
     *
     * <p>Smali type format:
     * <ul>
     *   <li>Primitive types: I (int), Z (boolean), F (float), J (long), S (short), B (byte), D (double), C (char), V (void)</li>
     *   <li>Object types: Lpackage/name/ClassName; (e.g., Landroid/os/Bundle;)</li>
     *   <li>Array types: [ prefix (e.g., [I for int[], [Landroid/os/Bundle; for Bundle[])</li>
     * </ul>
     *
     * <p>Examples:
     * <ul>
     *   <li>"android.app.Activity->onCreate(Landroid/os/Bundle;)V" - method with Bundle parameter returning void</li>
     *   <li>"java.lang.String->substring(II)Ljava/lang/String;" - method with two int parameters returning String</li>
     *   <li>"com.example.MyClass->getData([I)Z" - method with int array parameter returning boolean</li>
     * </ul>
     *
     * @param signature the method signature in Smali format
     * @return a method match object
     */
    @NonNull
    MethodMatch exactMethod(@NonNull String signature);

    /**
     * Creates a match for the specified method object.
     *
     * @param method the method to match
     * @return a method match object
     */
    @NonNull
    MethodMatch exact(@NonNull Method method);

    /**
     * Finds a constructor by its exact signature.
     *
     * <p>The signature format is: "className-><init>(paramTypes)V"
     * where paramTypes are in Smali format and return type is always V (void).
     *
     * <p>Smali type format:
     * <ul>
     *   <li>Primitive types: I (int), Z (boolean), F (float), J (long), S (short), B (byte), D (double), C (char)</li>
     *   <li>Object types: Lpackage/name/ClassName; (e.g., Landroid/content/Context;)</li>
     *   <li>Array types: [ prefix (e.g., [I for int[], [Ljava/lang/String; for String[])</li>
     * </ul>
     *
     * <p>Examples:
     * <ul>
     *   <li>"android.app.Activity-><init>()V" - no-arg constructor</li>
     *   <li>"android.view.View-><init>(Landroid/content/Context;)V" - constructor with Context parameter</li>
     *   <li>"java.lang.String-><init>([C)V" - constructor with char array parameter</li>
     * </ul>
     *
     * @param signature the constructor signature in Smali format
     * @return a constructor match object
     */
    @NonNull
    ConstructorMatch exactConstructor(@NonNull String signature);

    /**
     * Creates a match for the specified constructor object.
     *
     * @param constructor the constructor to match
     * @return a constructor match object
     */
    @NonNull
    ConstructorMatch exact(@NonNull Constructor<?> constructor);

    /**
     * Finds a field by its exact signature.
     *
     * <p>The signature format is: "className->fieldName:fieldType"
     * where fieldType is in Smali format.
     *
     * <p>Smali type format:
     * <ul>
     *   <li>Primitive types: I (int), Z (boolean), F (float), J (long), S (short), B (byte), D (double), C (char)</li>
     *   <li>Object types: Lpackage/name/ClassName; (e.g., Ljava/lang/String;)</li>
     *   <li>Array types: [ prefix (e.g., [I for int[], [Ljava/lang/Object; for Object[])</li>
     * </ul>
     *
     * <p>Examples:
     * <ul>
     *   <li>"android.app.Activity->mFinished:Z" - boolean field</li>
     *   <li>"java.lang.Thread->name:Ljava/lang/String;" - String field</li>
     *   <li>"com.example.MyClass->data:[I" - int array field</li>
     * </ul>
     *
     * @param signature the field signature in Smali format
     * @return a field match object
     */
    @NonNull
    FieldMatch exactField(@NonNull String signature);

    /**
     * Creates a match for the specified field object.
     *
     * @param field the field to match
     * @return a field match object
     */
    @NonNull
    FieldMatch exact(@NonNull Field field);

    /**
     * Represents a method or constructor parameter.
     *
     * <p>This is a replacement for {@link java.lang.reflect.Parameter} which is not
     * available before Android O (API 26).
     */
    interface Parameter {
        /**
         * Returns the type of this parameter.
         *
         * @return the parameter type class
         */
        @NonNull
        Class<?> getType();

        /**
         * Returns the index of this parameter in its declaring executable.
         *
         * @return the zero-based parameter index
         */
        int getIndex();

        /**
         * Returns the method or constructor that declares this parameter.
         *
         * @return the declaring executable (Method or Constructor)
         */
        @NonNull
        Member getDeclaringExecutable();
    }

    /**
     * A functional interface that supplies values.
     *
     * @param <T> the type of values supplied
     */
    @FunctionalInterface
    interface Supplier<T> {
        /**
         * Gets a value.
         *
         * @return the supplied value
         */
        @NonNull
        T get();
    }

    /**
     * A functional interface that accepts a single argument.
     *
     * @param <T> the type of the argument
     */
    @FunctionalInterface
    interface Consumer<T> {
        /**
         * Performs this operation on the given argument.
         *
         * @param t the input argument
         */
        void accept(@NonNull T t);
    }

    /**
     * A functional interface that accepts two arguments.
     *
     * @param <T> the type of the first argument
     * @param <U> the type of the second argument
     */
    @FunctionalInterface
    interface BiConsumer<T, U> {
        /**
         * Performs this operation on the given arguments.
         *
         * @param t the first input argument
         * @param u the second input argument
         */
        void accept(@NonNull T t, @NonNull U u);
    }

    /**
     * A functional interface that tests a value.
     *
     * @param <T> the type of the value to test
     */
    @FunctionalInterface
    interface Predicate<T> {
        /**
         * Evaluates this predicate on the given argument.
         *
         * @param t the input argument
         * @return true if the test passes, false otherwise
         */
        boolean test(@NonNull T t);
    }

    /**
     * Indicates that this method requires DEX bytecode analysis.
     *
     * <p>DEX analysis is more expensive than reflection-based matching but provides
     * powerful capabilities like matching methods by their bytecode contents.
     */
    @RequiresOptIn(level = RequiresOptIn.Level.ERROR)
    @Retention(RetentionPolicy.CLASS)
    @Target({ElementType.METHOD})
    @interface DexAnalysis {
    }

    /**
     * Indicates that this method requires annotation analysis.
     *
     * <p>Annotation analysis examines runtime annotations on classes, methods, and fields.
     */
    @RequiresOptIn(level = RequiresOptIn.Level.ERROR)
    @Retention(RetentionPolicy.CLASS)
    @Target({ElementType.METHOD})
    @interface AnnotationAnalysis {
    }

    /**
     * Base interface for matching reflection elements based on their modifiers and metadata.
     *
     * @param <Self> the concrete matcher type for method chaining
     */
    interface ReflectMatcher<Self extends ReflectMatcher<Self>> {
        /**
         * Sets a key for caching this matcher's results.
         *
         * <p>Using keys enables efficient reuse of match results across multiple queries.
         *
         * @param key the cache key
         * @return this matcher for method chaining
         */
        @NonNull
        Self setKey(@NonNull String key);

        /**
         * Matches only public elements.
         *
         * @param isPublic true to match only public elements
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIsPublic(boolean isPublic);

        /**
         * Matches only private elements.
         *
         * @param isPrivate true to match only private elements
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIsPrivate(boolean isPrivate);

        /**
         * Matches only protected elements.
         *
         * @param isProtected true to match only protected elements
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIsProtected(boolean isProtected);

        /**
         * Matches only package-private elements.
         *
         * @param isPackage true to match only package-private elements
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIsPackage(boolean isPackage);
    }

    /**
     * Represents boolean logic for combining multiple match conditions.
     *
     * <p>Syntax allows building complex matching expressions using AND, OR, and NOT operations.
     *
     * @param <Match> the type of match this syntax operates on
     */
    interface Syntax<Match extends BaseMatch<Match, ?>> {
        /**
         * Combines this syntax with another using logical AND.
         *
         * <p>Both conditions must be satisfied for the match to succeed.
         *
         * @param predicate the syntax to AND with this one
         * @return a new syntax representing the AND operation
         */
        @NonNull
        Syntax<Match> and(@NonNull Syntax<Match> predicate);

        /**
         * Combines this syntax with another using logical OR.
         *
         * <p>At least one condition must be satisfied for the match to succeed.
         *
         * @param predicate the syntax to OR with this one
         * @return a new syntax representing the OR operation
         */
        @NonNull
        Syntax<Match> or(@NonNull Syntax<Match> predicate);

        /**
         * Negates this syntax using logical NOT.
         *
         * <p>The match succeeds only if this condition is NOT satisfied.
         *
         * @return a new syntax representing the NOT operation
         */
        @NonNull
        Syntax<Match> not();
    }

    /**
     * Matcher for filtering classes based on various criteria.
     */
    interface ClassMatcher extends ReflectMatcher<ClassMatcher> {
        /**
         * Matches classes by name pattern.
         *
         * @param name the string match for the class name
         * @return this matcher for method chaining
         */
        @NonNull
        ClassMatcher setName(@NonNull StringMatch name);

        /**
         * Matches classes by their superclass.
         *
         * @param superClassMatch the match for the superclass
         * @return this matcher for method chaining
         */
        @NonNull
        ClassMatcher setSuperClass(@NonNull ClassMatch superClassMatch);

        /**
         * Matches classes that implement specific interfaces.
         *
         * @param syntax the syntax for matching interfaces
         * @return this matcher for method chaining
         */
        @NonNull
        ClassMatcher setContainsInterfaces(@NonNull Syntax<ClassMatch> syntax);

        /**
         * Matches abstract or concrete classes.
         *
         * @param isAbstract true to match only abstract classes
         * @return this matcher for method chaining
         */
        @NonNull
        ClassMatcher setIsAbstract(boolean isAbstract);

        /**
         * Matches static or non-static nested classes.
         *
         * @param isStatic true to match only static nested classes
         * @return this matcher for method chaining
         */
        @NonNull
        ClassMatcher setIsStatic(boolean isStatic);

        /**
         * Matches final or non-final classes.
         *
         * @param isFinal true to match only final classes
         * @return this matcher for method chaining
         */
        @NonNull
        ClassMatcher setIsFinal(boolean isFinal);

        /**
         * Matches interfaces or classes.
         *
         * @param isInterface true to match only interfaces
         * @return this matcher for method chaining
         */
        @NonNull
        ClassMatcher setIsInterface(boolean isInterface);
    }

    /**
     * Matcher for filtering method/constructor parameters.
     */
    interface ParameterMatcher extends ReflectMatcher<ParameterMatcher> {
        /**
         * Matches parameters at a specific index.
         *
         * @param index the zero-based parameter index
         * @return this matcher for method chaining
         */
        @NonNull
        ParameterMatcher setIndex(int index);

        /**
         * Matches parameters by type.
         *
         * @param type the class match for the parameter type
         * @return this matcher for method chaining
         */
        @NonNull
        ParameterMatcher setType(@NonNull ClassMatch type);

        /**
         * Matches final or non-final parameters (Android O+).
         *
         * @param isFinal true to match only final parameters
         * @return this matcher for method chaining
         */
        @RequiresApi(Build.VERSION_CODES.O)
        @NonNull
        ParameterMatcher setIsFinal(boolean isFinal);

        /**
         * Matches synthetic or non-synthetic parameters (Android O+).
         *
         * @param isSynthetic true to match only synthetic parameters
         * @return this matcher for method chaining
         */
        @RequiresApi(Build.VERSION_CODES.O)
        @NonNull
        ParameterMatcher setIsSynthetic(boolean isSynthetic);

        /**
         * Matches varargs or regular parameters (Android O+).
         *
         * @param isVarargs true to match only varargs parameters
         * @return this matcher for method chaining
         */
        @RequiresApi(Build.VERSION_CODES.O)
        @NonNull
        ParameterMatcher setIsVarargs(boolean isVarargs);

        /**
         * Matches implicit or explicit parameters (Android O+).
         *
         * <p>Implicit parameters are added by the compiler (e.g., outer class reference).
         *
         * @param isImplicit true to match only implicit parameters
         * @return this matcher for method chaining
         */
        @RequiresApi(Build.VERSION_CODES.O)
        @NonNull
        ParameterMatcher setIsImplicit(boolean isImplicit);
    }

    /**
     * Base matcher for class members (methods, constructors, fields).
     *
     * @param <Self> the concrete matcher type for method chaining
     */
    interface MemberMatcher<Self extends MemberMatcher<Self>> extends ReflectMatcher<Self> {
        /**
         * Matches members declared in a specific class.
         *
         * @param declaringClassMatch the match for the declaring class
         * @return this matcher for method chaining
         */
        @NonNull
        Self setDeclaringClass(@NonNull ClassMatch declaringClassMatch);

        /**
         * Matches synthetic or non-synthetic members.
         *
         * <p>Synthetic members are generated by the compiler and not present in source code.
         *
         * @param isSynthetic true to match only synthetic members
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIsSynthetic(boolean isSynthetic);

        /**
         * Includes members from superclasses in the search.
         *
         * @param includeSuper true to search superclasses
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIncludeSuper(boolean includeSuper);

        /**
         * Includes members from implemented interfaces in the search.
         *
         * @param includeInterface true to search interfaces
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIncludeInterface(boolean includeInterface);
    }

    /**
     * Matcher for filtering fields based on various criteria.
     */
    interface FieldMatcher extends MemberMatcher<FieldMatcher> {
        /**
         * Matches fields by name pattern.
         *
         * @param name the string match for the field name
         * @return this matcher for method chaining
         */
        @NonNull
        FieldMatcher setName(@NonNull StringMatch name);

        /**
         * Matches fields by type.
         *
         * @param type the class match for the field type
         * @return this matcher for method chaining
         */
        @NonNull
        FieldMatcher setType(@NonNull ClassMatch type);

        /**
         * Matches static or instance fields.
         *
         * @param isStatic true to match only static fields
         * @return this matcher for method chaining
         */
        @NonNull
        FieldMatcher setIsStatic(boolean isStatic);

        /**
         * Matches final or non-final fields.
         *
         * @param isFinal true to match only final fields
         * @return this matcher for method chaining
         */
        @NonNull
        FieldMatcher setIsFinal(boolean isFinal);

        /**
         * Matches transient or non-transient fields.
         *
         * @param isTransient true to match only transient fields
         * @return this matcher for method chaining
         */
        @NonNull
        FieldMatcher setIsTransient(boolean isTransient);

        /**
         * Matches volatile or non-volatile fields.
         *
         * @param isVolatile true to match only volatile fields
         * @return this matcher for method chaining
         */
        @NonNull
        FieldMatcher setIsVolatile(boolean isVolatile);
    }

    /**
     * Base matcher for executable members (methods and constructors).
     *
     * <p>Provides powerful matching capabilities including parameter matching and
     * DEX bytecode analysis features like matching by invoked methods or referenced strings.
     *
     * @param <Self> the concrete matcher type for method chaining
     */
    interface ExecutableMatcher<Self extends ExecutableMatcher<Self>> extends MemberMatcher<Self> {
        /**
         * Matches executables with a specific number of parameters.
         *
         * @param count the parameter count
         * @return this matcher for method chaining
         */
        @NonNull
        Self setParameterCount(int count);

        /**
         * Matches executables by parameter criteria using syntax.
         *
         * <p>This method allows matching methods or constructors based on their parameter types,
         * positions, and other characteristics. It accepts a {@link Syntax} object containing
         * parameter matching rules.
         *
         * <p><b>Example 1: Match method with specific parameter types in order</b>
         * <pre>{@code
         * builder.firstMethod(m -> m
         *     .setDeclaringClass(builder.exactClass("com.example.MyClass"))
         *     .setName(builder.exact("myMethod"))
         *     // Match method with parameters (String, int, boolean)
         *     .setParameters(m.conjunction(
         *         String.class,
         *         int.class,
         *         boolean.class
         *     ))
         * ).onMatch(method -> {
         *     hook(method, MyHooker.class);
         * });
         * }</pre>
         *
         * <p><b>Example 2: Match method with parameter at specific index</b>
         * <pre>{@code
         * builder.firstMethod(m -> m
         *     .setDeclaringClass(builder.exactClass("com.example.MyClass"))
         *     .setName(builder.exact("processData"))
         *     // Match method where the second parameter (index 1) is a String
         *     .setParameters(m.observe(1, String.class))
         * ).onMatch(method -> {
         *     hook(method, MyHooker.class);
         * });
         * }</pre>
         *
         * <p><b>Example 3: Match method with parameter using ClassMatch</b>
         * <pre>{@code
         * builder.firstMethod(m -> m
         *     .setDeclaringClass(builder.exactClass("com.example.MyClass"))
         *     .setName(builder.exact("handle"))
         *     // Match method where first parameter extends/implements specific class
         *     .setParameters(m.observe(0,
         *         builder.firstClass(c -> c
         *             .setName(builder.contains("Handler"))
         *         )
         *     ))
         * ).onMatch(method -> {
         *     hook(method, MyHooker.class);
         * });
         * }</pre>
         *
         * <p><b>Example 4: Match method with complex parameter matching</b>
         * <pre>{@code
         * builder.firstMethod(m -> m
         *     .setDeclaringClass(builder.exactClass("com.example.MyClass"))
         *     .setName(builder.exact("complexMethod"))
         *     // Match using firstParameter for detailed parameter criteria
         *     .setParameters(m.firstParameter(p -> p
         *         .setIndex(0)
         *         .setType(builder.firstClass(c -> c
         *             .setName(builder.exact("android.content.Context"))
         *         ))
         *     ).observe())
         * ).onMatch(method -> {
         *     hook(method, MyHooker.class);
         * });
         * }</pre>
         *
         * <p><b>Example 5: Match method with multiple specific parameters</b>
         * <pre>{@code
         * // Match method with parameters: (Context, String, int[])
         * builder.firstMethod(m -> m
         *     .setDeclaringClass(builder.exactClass("com.example.Service"))
         *     .setName(builder.exact("initialize"))
         *     .setParameters(m.conjunction(
         *         builder.exactClass("android.content.Context"),
         *         builder.exactClass(String.class),
         *         builder.exactClass(int[].class)
         *     ))
         * ).onMatch(method -> {
         *     hook(method, MyHooker.class);
         * });
         * }</pre>
         *
         * @param parameters the syntax for matching parameters
         * @return this matcher for method chaining
         * @see #conjunction(Class[])
         * @see #conjunction(ClassMatch[])
         * @see #observe(int, Class)
         * @see #observe(int, ClassMatch)
         * @see #firstParameter(Consumer)
         * @see #parameters(Consumer)
         */
        @NonNull
        Self setParameters(@NonNull Syntax<ParameterMatch> parameters);

        /**
         * Matches executables that reference specific strings in their bytecode.
         *
         * <p>This requires DEX analysis and can match methods by the string literals they use.
         *
         * @param referredStrings the syntax for matching referenced strings
         * @return this matcher for method chaining
         */
        @DexAnalysis
        @NonNull
        Self setReferredStrings(@NonNull Syntax<StringMatch> referredStrings);

        /**
         * Matches executables that assign values to specific fields.
         *
         * <p>This requires DEX analysis and can match methods by the fields they write to.
         *
         * @param assignedFields the syntax for matching assigned fields
         * @return this matcher for method chaining
         */
        @DexAnalysis
        @NonNull
        Self setAssignedFields(@NonNull Syntax<FieldMatch> assignedFields);

        /**
         * Matches executables that read from specific fields.
         *
         * <p>This requires DEX analysis and can match methods by the fields they read from.
         *
         * @param accessedFields the syntax for matching accessed fields
         * @return this matcher for method chaining
         */
        @DexAnalysis
        @NonNull
        Self setAccessedFields(@NonNull Syntax<FieldMatch> accessedFields);

        /**
         * Matches executables that invoke specific methods.
         *
         * <p>This requires DEX analysis and can match methods by the methods they call.
         *
         * @param invokedMethods the syntax for matching invoked methods
         * @return this matcher for method chaining
         */
        @DexAnalysis
        @NonNull
        Self setInvokedMethods(@NonNull Syntax<MethodMatch> invokedMethods);

        /**
         * Matches executables that invoke specific constructors.
         *
         * <p>This requires DEX analysis and can match methods by the constructors they call.
         *
         * @param invokedConstructors the syntax for matching invoked constructors
         * @return this matcher for method chaining
         */
        @DexAnalysis
        @NonNull
        Self setInvokedConstructors(@NonNull Syntax<ConstructorMatch> invokedConstructors);

        /**
         * Matches executables that contain specific bytecode opcodes.
         *
         * <p>This requires DEX analysis and can match methods by their bytecode patterns.
         *
         * @param opcodes the DEX opcodes to search for
         * @return this matcher for method chaining
         */
        @DexAnalysis
        @NonNull
        Self setContainsOpcodes(@NonNull byte[] opcodes);

        /**
         * Matches varargs or regular executables.
         *
         * @param isVarargs true to match only varargs executables
         * @return this matcher for method chaining
         */
        @NonNull
        Self setIsVarargs(boolean isVarargs);

        /**
         * Creates a conjunction (AND) of parameter matches for multiple types.
         *
         * <p>All parameters must match their corresponding types in order.
         *
         * @param types the class matches for each parameter
         * @return a syntax representing all parameters matching
         */
        @NonNull
        Syntax<ParameterMatch> conjunction(@NonNull ClassMatch... types);

        /**
         * Creates a conjunction (AND) of parameter matches for multiple types.
         *
         * @param types the classes for each parameter
         * @return a syntax representing all parameters matching
         */
        @NonNull
        Syntax<ParameterMatch> conjunction(@NonNull Class<?>... types);

        /**
         * Creates a match for a parameter at a specific index with a specific type.
         *
         * @param index the zero-based parameter index
         * @param types the class match for the parameter type
         * @return a syntax for the parameter match
         */
        @NonNull
        Syntax<ParameterMatch> observe(int index, @NonNull ClassMatch types);

        /**
         * Creates a match for a parameter at a specific index with a specific type.
         *
         * @param index the zero-based parameter index
         * @param types the class for the parameter type
         * @return a syntax for the parameter match
         */
        @NonNull
        Syntax<ParameterMatch> observe(int index, @NonNull Class<?> types);

        /**
         * Finds the first parameter matching the specified criteria.
         *
         * @param consumer consumer that configures the parameter matcher
         * @return a match for the first matching parameter
         */
        @NonNull
        ParameterMatch firstParameter(@NonNull Consumer<ParameterMatcher> consumer);

        /**
         * Creates a lazy sequence of parameters matching the specified criteria.
         *
         * @param consumer consumer that configures the parameter matcher
         * @return a lazy sequence of matching parameters
         */
        @NonNull
        ParameterLazySequence parameters(@NonNull Consumer<ParameterMatcher> consumer);
    }

    /**
     * Matcher for filtering methods based on various criteria.
     */
    interface MethodMatcher extends ExecutableMatcher<MethodMatcher> {
        /**
         * Matches methods by name pattern.
         *
         * @param name the string match for the method name
         * @return this matcher for method chaining
         */
        @NonNull
        MethodMatcher setName(@NonNull StringMatch name);

        /**
         * Matches methods by return type.
         *
         * @param returnType the class match for the return type
         * @return this matcher for method chaining
         */
        @NonNull
        MethodMatcher setReturnType(@NonNull ClassMatch returnType);

        /**
         * Matches abstract or concrete methods.
         *
         * @param isAbstract true to match only abstract methods
         * @return this matcher for method chaining
         */
        @NonNull
        MethodMatcher setIsAbstract(boolean isAbstract);

        /**
         * Matches static or instance methods.
         *
         * @param isStatic true to match only static methods
         * @return this matcher for method chaining
         */
        @NonNull
        MethodMatcher setIsStatic(boolean isStatic);

        /**
         * Matches final or non-final methods.
         *
         * @param isFinal true to match only final methods
         * @return this matcher for method chaining
         */
        @NonNull
        MethodMatcher setIsFinal(boolean isFinal);

        /**
         * Matches synchronized or non-synchronized methods.
         *
         * @param isSynchronized true to match only synchronized methods
         * @return this matcher for method chaining
         */
        @NonNull
        MethodMatcher setIsSynchronized(boolean isSynchronized);

        /**
         * Matches native or non-native methods.
         *
         * @param isNative true to match only native methods
         * @return this matcher for method chaining
         */
        @NonNull
        MethodMatcher setIsNative(boolean isNative);
    }

    /**
     * Matcher for filtering constructors.
     *
     * <p>Constructors inherit all matching capabilities from ExecutableMatcher
     * including parameter matching and DEX analysis features.
     */
    interface ConstructorMatcher extends ExecutableMatcher<ConstructorMatcher> {
    }

    /**
     * Base interface for match results.
     *
     * @param <Self> the concrete match type for method chaining
     * @param <Reflect> the type of reflection object matched
     */
    interface BaseMatch<Self extends BaseMatch<Self, Reflect>, Reflect> {
        /**
         * Returns a syntax for combining this match with others.
         *
         * @return a syntax object for boolean operations
         */
        @NonNull
        Syntax<Self> observe();

        /**
         * Returns a reversed view of this match for collection operations.
         *
         * @return a syntax with reversed ordering
         */
        @NonNull
        Syntax<Self> reverse();
    }

    /**
     * A match result for reflection elements with callback and binding support.
     *
     * @param <Self> the concrete match type for method chaining
     * @param <Reflect> the type of reflection object matched
     * @param <Matcher> the matcher type used to create this match
     */
    interface ReflectMatch<Self extends ReflectMatch<Self, Reflect, Matcher>, Reflect, Matcher extends ReflectMatcher<Matcher>> extends BaseMatch<Self, Reflect> {
        /**
         * Gets the cache key associated with this match.
         *
         * @return the cache key, or null if not set
         */
        @Nullable
        String getKey();

        /**
         * Sets a cache key for this match result.
         *
         * @param key the cache key
         * @return this match for method chaining
         */
        @NonNull
        Self setKey(@Nullable String key);

        /**
         * Registers a callback to be invoked when this match succeeds.
         *
         * <p>The callback receives the matched reflection object.
         *
         * @param consumer the callback to invoke with the match result
         * @return this match for method chaining
         */
        @NonNull
        Self onMatch(@NonNull Consumer<Reflect> consumer);

        /**
         * Registers a callback to be invoked when this match fails.
         *
         * @param handler the callback to invoke on match failure
         * @return this match for method chaining
         */
        @NonNull
        Self onMiss(@NonNull Runnable handler);

        /**
         * Provides a substitute match to use if this match fails.
         *
         * @param substitute supplier that provides an alternative match
         * @return this match for method chaining
         */
        @NonNull
        Self substituteIfMiss(@NonNull Supplier<Self> substitute);

        /**
         * Attempts a different match if this one fails.
         *
         * @param consumer consumer that configures an alternative matcher
         * @return this match for method chaining
         */
        @NonNull
        Self matchFirstIfMiss(@NonNull Consumer<Matcher> consumer);

        /**
         * Binds this match to a LazyBind object.
         *
         * <p>The consumer will be invoked with the bind object and match result
         * when the match succeeds.
         *
         * @param bind the bind object to link with this match
         * @param consumer the callback to invoke on successful match
         * @param <Bind> the type of bind object
         * @return this match for method chaining
         */
        @NonNull
        <Bind extends LazyBind> Self bind(@NonNull Bind bind, @NonNull BiConsumer<Bind, Reflect> consumer);
    }

    /**
     * A match result for a Class.
     */
    interface ClassMatch extends ReflectMatch<ClassMatch, Class<?>, ClassMatcher> {
        /**
         * Gets the superclass of the matched class.
         *
         * @return a match for the superclass
         */
        @NonNull
        ClassMatch getSuperClass();

        /**
         * Gets all interfaces implemented by the matched class.
         *
         * @return a lazy sequence of interface classes
         */
        @NonNull
        ClassLazySequence getInterfaces();

        /**
         * Gets all methods declared by the matched class.
         *
         * <p>Does not include inherited methods unless specified in a matcher.
         *
         * @return a lazy sequence of declared methods
         */
        @NonNull
        MethodLazySequence getDeclaredMethods();

        /**
         * Gets all constructors declared by the matched class.
         *
         * @return a lazy sequence of declared constructors
         */
        @NonNull
        ConstructorLazySequence getDeclaredConstructors();

        /**
         * Gets all fields declared by the matched class.
         *
         * <p>Does not include inherited fields unless specified in a matcher.
         *
         * @return a lazy sequence of declared fields
         */
        @NonNull
        FieldLazySequence getDeclaredFields();

        /**
         * Gets the array type for this class.
         *
         * <p>For example, if this class is {@code String}, returns {@code String[]}.
         *
         * @return a match for the array type
         */
        @NonNull
        ClassMatch getArrayType();
    }

    /**
     * A match result for a method or constructor parameter.
     */
    interface ParameterMatch extends ReflectMatch<ParameterMatch, Parameter, ParameterMatcher> {
        /**
         * Gets the type of the matched parameter.
         *
         * @return a match for the parameter type
         */
        @NonNull
        ClassMatch getType();
    }

    /**
     * Base match result for class members (methods, constructors, fields).
     *
     * @param <Self> the concrete match type for method chaining
     * @param <Reflect> the type of member (Method, Constructor, or Field)
     * @param <Matcher> the matcher type used to create this match
     */
    interface MemberMatch<Self extends MemberMatch<Self, Reflect, Matcher>, Reflect extends Member, Matcher extends MemberMatcher<Matcher>> extends ReflectMatch<Self, Reflect, Matcher> {
        /**
         * Gets the class that declares the matched member.
         *
         * @return a match for the declaring class
         */
        @NonNull
        ClassMatch getDeclaringClass();
    }

    /**
     * Base match result for executable members (methods and constructors).
     *
     * @param <Self> the concrete match type for method chaining
     * @param <Reflect> the type of executable (Method or Constructor)
     * @param <Matcher> the matcher type used to create this match
     */
    interface ExecutableMatch<Self extends ExecutableMatch<Self, Reflect, Matcher>, Reflect extends Member, Matcher extends ExecutableMatcher<Matcher>> extends MemberMatch<Self, Reflect, Matcher> {
        /**
         * Gets the parameter types of the matched executable.
         *
         * @return a lazy sequence of parameter type classes
         */
        @NonNull
        ClassLazySequence getParameterTypes();

        /**
         * Gets the parameters of the matched executable.
         *
         * @return a lazy sequence of parameters
         */
        @NonNull
        ParameterLazySequence getParameters();

        /**
         * Gets all fields that the matched executable assigns values to.
         *
         * <p>This requires DEX analysis.
         *
         * @return a lazy sequence of assigned fields
         */
        @DexAnalysis
        @NonNull
        FieldLazySequence getAssignedFields();

        /**
         * Gets all fields that the matched executable reads from.
         *
         * <p>This requires DEX analysis.
         *
         * @return a lazy sequence of accessed fields
         */
        @DexAnalysis
        @NonNull
        FieldLazySequence getAccessedFields();

        /**
         * Gets all methods that the matched executable invokes.
         *
         * <p>This requires DEX analysis.
         *
         * @return a lazy sequence of invoked methods
         */
        @DexAnalysis
        @NonNull
        MethodLazySequence getInvokedMethods();

        /**
         * Gets all constructors that the matched executable invokes.
         *
         * <p>This requires DEX analysis.
         *
         * @return a lazy sequence of invoked constructors
         */
        @DexAnalysis
        @NonNull
        ConstructorLazySequence getInvokedConstructors();
    }

    /**
     * A match result for a Method.
     */
    interface MethodMatch extends ExecutableMatch<MethodMatch, Method, MethodMatcher> {
        /**
         * Gets the return type of the matched method.
         *
         * @return a match for the return type
         */
        @NonNull
        ClassMatch getReturnType();
    }

    /**
     * A match result for a Constructor.
     */
    interface ConstructorMatch extends ExecutableMatch<ConstructorMatch, Constructor<?>, ConstructorMatcher> {
    }

    /**
     * A match result for a Field.
     */
    interface FieldMatch extends MemberMatch<FieldMatch, Field, FieldMatcher> {
        /**
         * Gets the type of the matched field.
         *
         * @return a match for the field type
         */
        @NonNull
        ClassMatch getType();
    }

    /**
     * A match result for a String.
     */
    interface StringMatch extends BaseMatch<StringMatch, String> {

    }

    /**
     * A lazy sequence of match results that can be filtered, transformed, and iterated.
     *
     * <p>Lazy sequences defer computation until results are actually needed,
     * improving performance when dealing with large result sets.
     *
     * @param <Self> the concrete sequence type for method chaining
     * @param <Match> the type of individual matches in the sequence
     * @param <Reflect> the type of reflection objects in the sequence
     * @param <Matcher> the matcher type for filtering the sequence
     */
    interface LazySequence<Self extends LazySequence<Self, Match, Reflect, Matcher>, Match extends ReflectMatch<Match, Reflect, Matcher>, Reflect, Matcher extends ReflectMatcher<Matcher>> {
        /**
         * Gets the first element in this sequence.
         *
         * @return a match for the first element
         */
        @NonNull
        Match first();

        /**
         * Gets the first element matching additional criteria.
         *
         * @param consumer consumer that configures additional matching criteria
         * @return a match for the first matching element
         */
        @NonNull
        Match first(@NonNull Consumer<Matcher> consumer);

        /**
         * Filters all elements in the sequence by additional criteria.
         *
         * @param consumer consumer that configures filtering criteria
         * @return this sequence filtered by the criteria
         */
        @NonNull
        Self all(@NonNull Consumer<Matcher> consumer);

        /**
         * Registers a callback to be invoked when matches are found.
         *
         * @param consumer callback that receives an iterable of matched elements
         * @return this sequence for method chaining
         */
        @NonNull
        Self onMatch(@NonNull Consumer<Iterable<Reflect>> consumer);

        /**
         * Registers a callback to be invoked when no matches are found.
         *
         * @param runnable callback to invoke on match failure
         * @return this sequence for method chaining
         */
        @NonNull
        Self onMiss(@NonNull Runnable runnable);

        /**
         * Creates a conjunction (AND) syntax for combining multiple matches.
         *
         * @return a syntax for AND operations on sequence elements
         */
        @NonNull
        Syntax<Match> conjunction();

        /**
         * Creates a disjunction (OR) syntax for combining multiple matches.
         *
         * @return a syntax for OR operations on sequence elements
         */
        @NonNull
        Syntax<Match> disjunction();

        /**
         * Provides a substitute sequence if this one is empty.
         *
         * @param substitute supplier that provides an alternative sequence
         * @return this sequence for method chaining
         */
        @NonNull
        Self substituteIfMiss(@NonNull Supplier<Self> substitute);

        /**
         * Attempts a different match if this sequence is empty.
         *
         * @param consumer consumer that configures an alternative matcher
         * @return this sequence for method chaining
         */
        @NonNull
        Self matchIfMiss(@NonNull Consumer<Matcher> consumer);

        /**
         * Binds this sequence to a LazyBind object.
         *
         * @param bind the bind object to link with this sequence
         * @param consumer callback invoked with the bind and matched elements
         * @param <Bind> the type of bind object
         * @return this sequence for method chaining
         */
        @NonNull
        <Bind extends LazyBind> Self bind(@NonNull Bind bind, @NonNull BiConsumer<Bind, Iterable<Reflect>> consumer);
    }

    /**
     * A lazy sequence of Class matches with additional class-specific operations.
     */
    interface ClassLazySequence extends LazySequence<ClassLazySequence, ClassMatch, Class<?>, ClassMatcher> {
        /**
         * Finds methods within all classes in this sequence.
         *
         * @param matcher consumer that configures method matching criteria
         * @return a lazy sequence of matching methods
         */
        @NonNull
        MethodLazySequence methods(@NonNull Consumer<MethodMatcher> matcher);

        /**
         * Finds the first method within all classes in this sequence.
         *
         * @param matcher consumer that configures method matching criteria
         * @return a match for the first matching method
         */
        @NonNull
        MethodMatch firstMethod(@NonNull Consumer<MethodMatcher> matcher);

        /**
         * Finds constructors within all classes in this sequence.
         *
         * @param matcher consumer that configures constructor matching criteria
         * @return a lazy sequence of matching constructors
         */
        @NonNull
        ConstructorLazySequence constructors(@NonNull Consumer<ConstructorMatcher> matcher);

        /**
         * Finds the first constructor within all classes in this sequence.
         *
         * @param matcher consumer that configures constructor matching criteria
         * @return a match for the first matching constructor
         */
        @NonNull
        ConstructorMatch firstConstructor(@NonNull Consumer<ConstructorMatcher> matcher);

        /**
         * Finds fields within all classes in this sequence.
         *
         * @param matcher consumer that configures field matching criteria
         * @return a lazy sequence of matching fields
         */
        @NonNull
        FieldLazySequence fields(@NonNull Consumer<FieldMatcher> matcher);

        /**
         * Finds the first field within all classes in this sequence.
         *
         * @param matcher consumer that configures field matching criteria
         * @return a match for the first matching field
         */
        @NonNull
        FieldMatch firstField(@NonNull Consumer<FieldMatcher> matcher);
    }

    /**
     * A lazy sequence of Parameter matches with type-specific operations.
     */
    interface ParameterLazySequence extends LazySequence<ParameterLazySequence, ParameterMatch, Parameter, ParameterMatcher> {
        /**
         * Gets the types of all parameters in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a lazy sequence of parameter types
         */
        @NonNull
        ClassLazySequence types(@NonNull Consumer<ClassMatcher> matcher);

        /**
         * Gets the type of the first parameter in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a match for the first parameter type
         */
        @NonNull
        ClassMatch firstType(@NonNull Consumer<ClassMatcher> matcher);
    }

    /**
     * Base lazy sequence for class members (methods, constructors, fields).
     *
     * @param <Self> the concrete sequence type for method chaining
     * @param <Match> the type of individual member matches
     * @param <Reflect> the type of member objects
     * @param <Matcher> the matcher type for filtering members
     */
    interface MemberLazySequence<Self extends MemberLazySequence<Self, Match, Reflect, Matcher>, Match extends MemberMatch<Match, Reflect, Matcher>, Reflect extends Member, Matcher extends MemberMatcher<Matcher>> extends LazySequence<Self, Match, Reflect, Matcher> {
        /**
         * Gets the declaring classes of all members in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a lazy sequence of declaring classes
         */
        @NonNull
        ClassLazySequence declaringClasses(@NonNull Consumer<ClassMatcher> matcher);

        /**
         * Gets the declaring class of the first member in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a match for the first declaring class
         */
        @NonNull
        ClassMatch firstDeclaringClass(@NonNull Consumer<ClassMatcher> matcher);
    }

    /**
     * A lazy sequence of Field matches with type-specific operations.
     */
    interface FieldLazySequence extends MemberLazySequence<FieldLazySequence, FieldMatch, Field, FieldMatcher> {
        /**
         * Gets the types of all fields in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a lazy sequence of field types
         */
        @NonNull
        ClassLazySequence types(@NonNull Consumer<ClassMatcher> matcher);

        /**
         * Gets the type of the first field in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a match for the first field type
         */
        @NonNull
        ClassMatch firstType(@NonNull Consumer<ClassMatcher> matcher);
    }

    /**
     * Base lazy sequence for executable members (methods and constructors).
     *
     * @param <Self> the concrete sequence type for method chaining
     * @param <Match> the type of individual executable matches
     * @param <Reflect> the type of executable objects
     * @param <Matcher> the matcher type for filtering executables
     */
    interface ExecutableLazySequence<Self extends ExecutableLazySequence<Self, Match, Reflect, Matcher>, Match extends ExecutableMatch<Match, Reflect, Matcher>, Reflect extends Member, Matcher extends ExecutableMatcher<Matcher>> extends MemberLazySequence<Self, Match, Reflect, Matcher> {
        /**
         * Gets parameters from all executables in this sequence.
         *
         * @param matcher consumer that configures parameter matching criteria
         * @return a lazy sequence of parameters
         */
        @NonNull
        ParameterLazySequence parameters(@NonNull Consumer<ParameterMatcher> matcher);

        /**
         * Gets the first parameter from all executables in this sequence.
         *
         * @param matcher consumer that configures parameter matching criteria
         * @return a match for the first parameter
         */
        @NonNull
        ParameterMatch firstParameter(@NonNull Consumer<ParameterMatcher> matcher);
    }

    /**
     * A lazy sequence of Method matches with return type operations.
     */
    interface MethodLazySequence extends ExecutableLazySequence<MethodLazySequence, MethodMatch, Method, MethodMatcher> {
        /**
         * Gets the return types of all methods in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a lazy sequence of return types
         */
        @NonNull
        ClassLazySequence returnTypes(@NonNull Consumer<ClassMatcher> matcher);

        /**
         * Gets the return type of the first method in this sequence.
         *
         * @param matcher consumer that configures class matching criteria
         * @return a match for the first return type
         */
        @NonNull
        ClassMatch firstReturnType(@NonNull Consumer<ClassMatcher> matcher);
    }

    /**
     * A lazy sequence of Constructor matches.
     */
    interface ConstructorLazySequence extends ExecutableLazySequence<ConstructorLazySequence, ConstructorMatch, Constructor<?>, ConstructorMatcher> {
    }

    /**
     * A bind object for coordinating matches and callbacks.
     *
     * <p>LazyBind allows synchronization of multiple match operations,
     * with callbacks for when all matches succeed or any match fails.
     */
    interface LazyBind {
        /**
         * Callback invoked when the associated match succeeds.
         */
        void onMatch();

        /**
         * Callback invoked when the associated match fails.
         */
        void onMiss();
    }
}
