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
    // Target Java 11 - lowest non-EOL LTS version
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11

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
    implementation("com.fasterxml.jackson.core:jackson-databind:2.21.0")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:6.0.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
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
                url.set("https://github.com/prodnull/unix-oidc/tree/main/java-oauth-dpop")

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
                    connection.set("scm:git:git://github.com/prodnull/unix-oidc.git")
                    developerConnection.set("scm:git:ssh://github.com/prodnull/unix-oidc.git")
                    url.set("https://github.com/prodnull/unix-oidc/tree/main/java-oauth-dpop")
                }
            }
        }
    }
}
