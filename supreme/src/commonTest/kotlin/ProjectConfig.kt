package io.kotest.provided
import at.asitplus.test.XmlReportingProjectConfig
import at.asitplus.test.JUnitXmlReporter
import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.extensions.Extension

/**
 * Multiplatform Kotest project configuration that records
 *  • every finished TestCase
 *  • every single invocation of those tests
 */
class ProjectConfig : XmlReportingProjectConfig()