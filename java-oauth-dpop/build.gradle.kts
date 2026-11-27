plugins {
    `java-library`
    `maven-publish`
    application
}

application {
    mainClass.set("com.github.prodnull.oauthdpop.crosstest.CrossTest")
}

group = "com.github.prodnull"
version = "0.1.0"

java {
    // Target Java 17. This is the real floor: Eclipse Collections 13 ships
    // Java 17 bytecode and JUnit 6 requires 17+, so an 11 target could never
    // actually run. Consumers on 17 and 21 are both supported.
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17

    withJavadocJar()
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    // Eclipse Collections for high-performance collections
    implementation("org.eclipse.collections:eclipse-collections-api:13.0.0")
    implementation("org.eclipse.collections:eclipse-collections:13.0.0")

    // JSON processing
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.0")

    // Testing (JUnit 6 requires Java 17+, matching the library target)
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// Compile with --release so that building on a newer JDK (CI uses 21) cannot
// accidentally link against APIs that do not exist on Java 17.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])

            pom {
                name.set("OAuth DPoP")
                description.set("OAuth 2.0 DPoP (Demonstrating Proof of Possession) implementation per RFC 9449")
                url.set("https://github.com/prodnull/prmana/tree/main/java-oauth-dpop")

                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/prodnull/prmana.git")
                    developerConnection.set("scm:git:ssh://github.com/prodnull/prmana.git")
                    url.set("https://github.com/prodnull/prmana/tree/main/java-oauth-dpop")
                }
            }
        }
    }
}
