package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificatePolicyException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.PolicyQualifierInfo
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodeCertificatePolicies
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodeInhibitAnyPolicy
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodePolicyConstraints
import at.asitplus.signum.indispensable.pki.pkiExtensions.decodePolicyMappings

/*
* PolicyValidator checks policy information on X509Certificate path
* */
class PolicyValidator(
    initialPolicies: Set<ObjectIdentifier>,
    expPolicyRequired: Boolean,
    polMappingInhibited: Boolean,
    anyPolicyInhibited: Boolean,
    private val certPathLen: Int,
    private val rejectPolicyQualifiers: Boolean,
    var rootNode: PolicyNode?
) : Validator {
    private val initPolicies: Set<ObjectIdentifier> =
        initialPolicies.ifEmpty { setOf(KnownOIDs.anyPolicy) }.toSet()
    private var explicitPolicy: Int = 0
    private var policyMapping: Int = 0
    private var inhibitAnyPolicy: Int = 0
    private var certIndex: Int = 0

    private var supportedExtensions: Set<ObjectIdentifier>? = null

    init {
        certIndex = 1
        explicitPolicy = if (expPolicyRequired) 0 else certPathLen + 1
        policyMapping = if (polMappingInhibited) 0 else certPathLen + 1
        inhibitAnyPolicy = if (anyPolicyInhibited) 0 else certPathLen + 1
    }

    override fun check(currCert: X509Certificate) {
        rootNode = processPolicies(
            certIndex,
            initPolicies,
            explicitPolicy,
            policyMapping,
            inhibitAnyPolicy,
            rejectPolicyQualifiers,
            rootNode,
            currCert,
            certIndex == certPathLen
        )

        if (certIndex != certPathLen) {
            explicitPolicy = updateExplicitPolicy(explicitPolicy, currCert, false)
            policyMapping = updatePolicyMapping(policyMapping, currCert)
            inhibitAnyPolicy = updateInhibitAnyPolicy(inhibitAnyPolicy, currCert)
        }
        certIndex++
    }

    /*
    * Adjusts value of explicitPolicy based on the requireExplicitPolicy value in the PolicyConstraints
    * extension in currentCert
    * */
    private fun updateExplicitPolicy(
        currentValue: Int, currentCert: X509Certificate, isFinalCert: Boolean
    ): Int {
        var result = currentValue

        if (result > 0 && !currentCert.isSelfIssued()) {
            result--
        }

        val constraints =
            currentCert.findExtension(KnownOIDs.policyConstraints_2_5_29_36)?.decodePolicyConstraints()
                ?: return result

        val required = constraints.requireExplicitPolicy.toBigInteger().intValue()

        result = when {
            !isFinalCert && required != -1 && (result == -1 || required < result) -> required
            isFinalCert && required == 0 -> 0
            else -> result
        }

        return result
    }

    /*
    * Adjusts value of policyMapping based on the inhibitPolicyMapping value in PolicyConstraint
    * extension in currentCert
    * */
    private fun updatePolicyMapping(
        currentValue: Int, currentCert: X509Certificate
    ): Int {
        var result = currentValue

        if (result > 0 && !currentCert.isSelfIssued()) {
            result--
        }

        val constraints =
            currentCert.findExtension(KnownOIDs.policyConstraints_2_5_29_36)?.decodePolicyConstraints()
                ?: return result

        val inhibitMapping = constraints.inhibitPolicyMapping.toBigInteger().intValue()
        if (inhibitMapping != -1 && (result == -1 || inhibitMapping < result)) {
            result = inhibitMapping
        }

        return result
    }

    /*
    * Adjusts value of inhibitAnyPolicy based on the inhibitAnyPolicy extension in currentCert
    * */
    private fun updateInhibitAnyPolicy(
        currentValue: Int, currentCert: X509Certificate
    ): Int {
        var result = currentValue

        if (result > 0 && !currentCert.isSelfIssued()) {
            result--
        }

        val extensionValue =
            currentCert.findExtension(KnownOIDs.inhibitAnyPolicy)?.decodeInhibitAnyPolicy()

        return if (extensionValue != null && extensionValue != -1 && extensionValue < result) {
            extensionValue
        } else {
            result
        }
    }

    private fun processPolicies(
        certIndex: Int,
        initialPolicies: Set<ObjectIdentifier>,
        explicitPolicy: Int,
        policyMapping: Int,
        inhibitAnyPolicy: Int,
        rejectPolicyQualifiers: Boolean,
        originalRoot: PolicyNode?,
        currentCert: X509Certificate,
        isFinalCert: Boolean
    ): PolicyNode? {
        var isCritical = false
        val anyPolicyQualifiers = mutableSetOf<PolicyQualifierInfo>()
        var root = originalRoot?.copyTree()

        val policyExtension =
            currentCert.findExtension(KnownOIDs.certificatePolicies_2_5_29_32)

        // RFC 5280: 6.1.3 (d)
        if (policyExtension != null && root != null) {
            isCritical = policyExtension.critical
            val policies = policyExtension.decodeCertificatePolicies()

            var containsAnyPolicy = false

            for (policyInfo in policies) {
                val currentPolicyOid = policyInfo.oid

                if (currentPolicyOid == KnownOIDs.anyPolicy) {
                    containsAnyPolicy = true
                    anyPolicyQualifiers.addAll(policyInfo.policyQualifiers)
                    continue
                }

                // RFC 5280: 6.1.3 (d)(1)
                val qualifiers = policyInfo.policyQualifiers
                if (qualifiers.isNotEmpty() && rejectPolicyQualifiers && isCritical) {
                    throw Exception("Critical policy qualifiers present in certificate")
                }

                // RFC 5280: 6.1.3 (d)(1)(i)
                val matched = processParentNodes(
                    certIndex,
                    isCritical,
                    root,
                    currentPolicyOid,
                    qualifiers,
                    matchAnyPolicy = false
                )

                // RFC 5280: 6.1.3 (d)(1)(ii)
                if (!matched) {
                    processParentNodes(
                        certIndex,
                        isCritical,
                        root,
                        currentPolicyOid,
                        qualifiers,
                        matchAnyPolicy = true
                    )
                }
            }

            // RFC 5280: 6.1.3 (d)(2)
            if (containsAnyPolicy) {
                if (inhibitAnyPolicy > 0 || (!isFinalCert && currentCert.isSelfIssued())) {
                    processParentNodes(
                        certIndex,
                        isCritical,
                        root,
                        KnownOIDs.anyPolicy,
                        anyPolicyQualifiers,
                        matchAnyPolicy = true
                    )
                }
            }

            // RFC 5280: 6.1.3 (d)(3)
            root.prune(certIndex)
            if (root.children.isEmpty()) root = null
        } else if (policyExtension == null) {
            // RFC 5280: 6.1.3 (e)
            root = null
        }

        if (root != null && !isFinalCert) {
            // RFC 5280: 6.1.4 (a)-(b)
            root = processPolicyMappings(
                currentCert, certIndex, policyMapping, root, isCritical, anyPolicyQualifiers
            )
        }

        if (root != null && !initialPolicies.contains(KnownOIDs.anyPolicy)) {
            root = policyExtension?.let {
                removeInvalidNodes(root!!, certIndex, initialPolicies, it)
            }

            // RFC 5280: 6.1.5 (g)(iii)
            if (root != null && isFinalCert) {
                root = rewriteLeafNodes(certIndex, initialPolicies, root)
            }
        }

        if (isFinalCert) {
            // RFC 5280: 6.1.5 (a)-(b)
            this.explicitPolicy = updateExplicitPolicy(explicitPolicy, currentCert, true)
        }

        // RFC 5280: 6.1.3 (f)
        if (this.explicitPolicy == 0 && root == null) {
            throw CertificatePolicyException("Non-null policy tree required but policy tree is null")
        }

        return root
    }

    /*
    * RFC 5280: 6.1.5 (g)(iii)
    * Called at the end of validation (only for final certificate in the chain).
    * Replaces anyPolicy leaf nodes with nodes from initial policies that are not already leafs
    * */
    private fun rewriteLeafNodes(
        certIndex: Int, initialPolicies: Set<ObjectIdentifier>, root: PolicyNode
    ): PolicyNode? {
        val anyPolicyNodes = root.getPolicyNodesValid(certIndex, KnownOIDs.anyPolicy)
        if (anyPolicyNodes.isEmpty()) return root

        val anyNode = anyPolicyNodes.first()
        val parent = anyNode.parent as PolicyNode
        parent.deleteChild(anyNode)

        val unmatchedPolicies = initialPolicies.toMutableSet().apply {
            root.getPolicyNodes(certIndex).forEach { remove(it.validPolicy) }
        }

        if (unmatchedPolicies.isEmpty()) {
            root.prune(certIndex)
            return root.takeIf { it.children.isEmpty() }
        }

        unmatchedPolicies.forEach { policyOid ->
            PolicyNode(
                parent = parent,
                validPolicy = policyOid,
                qualifierSet = anyNode.qualifierSet,
                criticalityIndicator = anyNode.criticalityIndicator,
                expectedPolicySet = setOf(policyOid),
                generatedByPolicyMapping = false
            )
        }

        return root
    }

    /*
    * Attempts to add child policy nodes at the current depth (certIndex)
    * for the given policy OID, based on matching parent nodes at depth certIndex - 1.
    * */
    private fun processParentNodes(
        certIndex: Int,
        isCritical: Boolean,
        root: PolicyNode,
        currentPolicy: ObjectIdentifier,
        qualifiers: Set<PolicyQualifierInfo>,
        matchAnyPolicy: Boolean
    ): Boolean {
        val parentNodes = root.getPolicyNodesExpected(certIndex - 1, currentPolicy, matchAnyPolicy)
        if (parentNodes.isEmpty()) return false

        var foundMatch = false

        for (parentNode in parentNodes) {
            if (currentPolicy == KnownOIDs.anyPolicy) {
                parentNode.expectedPolicySet.forEach { expectedPolicy ->
                    val alreadyExists = parentNode.children.any { it.validPolicy == expectedPolicy }
                    if (!alreadyExists) {
                        PolicyNode(
                            parent = parentNode,
                            validPolicy = expectedPolicy,
                            qualifierSet = qualifiers.toMutableSet(),
                            criticalityIndicator = isCritical,
                            expectedPolicySet = setOf(expectedPolicy),
                            generatedByPolicyMapping = false
                        )
                        foundMatch = true
                    }
                }
            } else {
                PolicyNode(
                    parent = parentNode,
                    validPolicy = currentPolicy,
                    qualifierSet = qualifiers.toMutableSet(),
                    criticalityIndicator = isCritical,
                    expectedPolicySet = setOf(currentPolicy),
                    generatedByPolicyMapping = false
                )
                foundMatch = true
            }
        }

        return foundMatch
    }


    /*
    * RFC 5280: 6.1.4 (a)-(b)
    * Handles policy mappings
    * */
    private fun processPolicyMappings(
        certificate: X509Certificate,
        certDepth: Int,
        policyMappingValue: Int,
        root: PolicyNode,
        isCritical: Boolean,
        anyPolicyQualifiers: Set<PolicyQualifierInfo>
    ): PolicyNode? {
        val policyMappingsExtension =
            certificate.findExtension(KnownOIDs.policyMappings) ?: return root

        val mappings = policyMappingsExtension.decodePolicyMappings()
        var nodesRemoved = false

        for (mapping in mappings) {
            val issuerDomain = mapping.issuerDomain
            val subjectDomain = mapping.subjectDomain
            require(issuerDomain != KnownOIDs.anyPolicy) {
                "issuerDomainPolicy must not be ANY_POLICY"
            }

            require(subjectDomain != KnownOIDs.anyPolicy) {
                "subjectDomainPolicy must not be ANY_POLICY"
            }

            val issuerNodes = root.getPolicyNodesValid(certDepth, issuerDomain)

            if (issuerNodes.isNotEmpty()) {
                issuerNodes.forEach { node ->
                    when {
                        policyMappingValue > 0 || policyMappingValue == -1 -> {
                            node.addExpectedPolicy(subjectDomain)
                        }

                        policyMappingValue == 0 -> {
                            node.parent?.deleteChild(node)
                            nodesRemoved = true
                        }
                    }
                }
            } else if (policyMappingValue > 0 || policyMappingValue == -1) {
                val anyPolicyNodes = root.getPolicyNodesValid(certDepth, KnownOIDs.anyPolicy)
                for (anyNode in anyPolicyNodes) {
                    val parent = anyNode.parent ?: continue
                    PolicyNode(
                        parent = parent,
                        validPolicy = issuerDomain,
                        qualifierSet = anyPolicyQualifiers.toMutableSet(),
                        criticalityIndicator = isCritical,
                        expectedPolicySet = setOf(subjectDomain),
                        generatedByPolicyMapping = true
                    )
                }
            }
        }

        if (nodesRemoved) {
            root.prune(certDepth)
            if (root.children.isEmpty()) return null
        }

        return root
    }

    /*
    * Part of the RFC 5280: 6.1.5 (g)(iii)
    * Removes nodes that don't intersect with the initial policies
    * */
    private fun removeInvalidNodes(
        root: PolicyNode,
        certDepth: Int,
        initialPolicies: Set<ObjectIdentifier>,
        currentExtension: X509CertificateExtension
    ): PolicyNode? {
        val currentPolicies = currentExtension.decodeCertificatePolicies()
        var removedAny = false

        for (policy in currentPolicies.map { it.oid }) {
            val matchingNodes = root.getPolicyNodesValid(certDepth, policy)

            for (node in matchingNodes) {
                val parent = node.parent ?: continue

                if (parent.validPolicy == KnownOIDs.anyPolicy && policy != KnownOIDs.anyPolicy && policy !in initialPolicies) {
                    parent.deleteChild(node)
                    removedAny = true
                }
            }
        }

        if (removedAny) {
            root.prune(certDepth)
            if (root.children.isEmpty()) return null
        }

        return root
    }
}