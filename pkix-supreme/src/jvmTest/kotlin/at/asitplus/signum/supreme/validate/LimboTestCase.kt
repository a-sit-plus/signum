package at.asitplus.signum.supreme.validate

import kotlinx.serialization.Serializable


@Serializable
data class LimboTestcase(
    val id: String,
    val conflicts_with: List<String>,
    val features: List<String>,
    val importance: String? = null,
    val description: String,
    val validation_kind: String,
    val trusted_certs: List<String>,
    val untrusted_intermediates: List<String>,
    val peer_certificate: String,
    val peer_certificate_key: String? = null,
    val validation_time: String? = null,
    val signature_algorithms: List<String>,
    val key_usage: List<String>,
    val extended_key_usage: List<String>,
    val expected_result: String,
    val expected_peer_name: LimboName? = null,
    val expected_peer_names: List<LimboName>,
    val max_chain_depth: Int? = null,
    val crls: List<String>
)

@Serializable
data class LimboName(
    val kind: String,
    val value: String
)

@Serializable
data class LimboSuite(
    val testcases: List<LimboTestcase>
)

