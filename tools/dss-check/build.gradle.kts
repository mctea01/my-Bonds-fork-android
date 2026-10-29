plugins { java; application }
repositories {
    maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
    mavenCentral()
}
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
tasks.withType<JavaCompile> { options.encoding = "UTF-8" }
dependencies {
    for (m in listOf("dss-pades-pdfbox", "dss-pades", "dss-cades", "dss-xades", "dss-asic-cades", "dss-asic-xades", "dss-validation", "dss-utils-apache-commons", "dss-crl-parser-x509crl", "dss-policy-jaxb", "dss-cms-object", "dss-diagnostic-jaxb", "dss-simple-report-jaxb", "dss-detailed-report-jaxb"))
        implementation("eu.europa.ec.joinup.sd-dss:$m:6.5")
    implementation("org.slf4j:slf4j-simple:2.0.20")
}
application { mainClass.set("dsscheck.Main") }
