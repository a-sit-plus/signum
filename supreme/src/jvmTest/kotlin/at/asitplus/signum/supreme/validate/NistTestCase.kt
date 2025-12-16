package at.asitplus.signum.supreme.validate

import kotlinx.serialization.Serializable

@Serializable
data class NistTestCase(
    val name: String,
    val root: String,
    val intermediates: List<String> = emptyList(),
    val leaf: String,
    val isSuccessful: Boolean,
    val failedValidator: String?,
    val errorMessage: String?,
    val explicitPolicyRequired: Boolean,
    val initialPolicies: List<String> = emptyList(),
    val anyPolicyInhibited: Boolean,
    val policyMappingInhibited: Boolean
)


