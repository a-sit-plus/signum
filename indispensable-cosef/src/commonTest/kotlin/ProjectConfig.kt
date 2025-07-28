package io.kotest.provided
import at.asitplus.test.XmlReportingProjectConfig
import at.asitplus.test.JUnitXmlReporter
import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.extensions.Extension

/** Wires KMP JUnit XML reporting */
class ProjectConfig : XmlReportingProjectConfig()