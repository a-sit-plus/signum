package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class PolicyValidator(
    initialPolicies: Set<ObjectIdentifier>,
    private val certPathLen: Int,
    private val expPolicyRequired: Boolean,
    private val polMappingInhibited: Boolean,
    private val anyPolicyInhibited: Boolean,
    private val rejectPolicyQualifiers: Boolean,
    private var rootNode: PolicyNode?
) {
    private val initPolicies: Set<ObjectIdentifier> = if (initialPolicies.isEmpty()) {
        setOf(KnownOIDs.anyPolicy)
    } else {
        initialPolicies.toSet()
    }
    private var explicitPolicy: Int = 0
    private var policyMapping: Int = 0
    private var inhibitAnyPolicy: Int = 0
    private var certIndex: Int = 0

    private var supportedExtensions: Set<String>? = null

    fun init() {
        certIndex = 1
        explicitPolicy = if (expPolicyRequired) 0 else certPathLen + 1
        policyMapping = if (polMappingInhibited) 0 else certPathLen + 1
        inhibitAnyPolicy = if (anyPolicyInhibited) 0 else certPathLen + 1
    }

    fun getSupportedExtensions(): MutableSet<String>? {
        if (supportedExtensions == null) {
            supportedExtensions = setOf(
                KnownOIDs.certificatePolicies.toString(),
                KnownOIDs.policyMappings.toString(),
                KnownOIDs.policyConstraints.toString(),
                KnownOIDs.inhibitAnyPolicy.toString()
            )
        }
        return supportedExtensions?.toMutableSet()
    }

    private fun checkPolicy(currCert: X509Certificate) {

        val finalCert = certIndex == certPathLen

        rootNode = processPolicies(
            certIndex,
            initPolicies,
            explicitPolicy,
            policyMapping,
            inhibitAnyPolicy,
            rejectPolicyQualifiers,
            rootNode,
            currCert,
            finalCert
        )

        if (!finalCert) {
            explicitPolicy = mergeExplicitPolicy(explicitPolicy, currCert, false)
            policyMapping = mergePolicyMapping(policyMapping, currCert)
            inhibitAnyPolicy = mergeInhibitAnyPolicy(inhibitAnyPolicy, currCert)
        }

        certIndex++
    }

    private fun mergeExplicitPolicy(
        currentValue: Int, currentCert: X509Certificate, isFinalCert: Boolean
    ): Int {
        var result = currentValue

        if (result > 0 && !currentCert.isSelfIssued()) {
            result--
        }

        val constraints =
            currentCert.findExtension(KnownOIDs.policyConstraints)?.decodePolicyConstraints()
                ?: return result

        val required = constraints.requireExplicitPolicy.toBigInteger().intValue()

        result = when {
            !isFinalCert && required != -1 && (result == -1 || required < result) -> required
            isFinalCert && required == 0 -> 0
            else -> result
        }

        return result
    }


    private fun mergePolicyMapping(
        currentValue: Int, currentCert: X509Certificate
    ): Int {
        var result = currentValue

        if (result > 0 && !currentCert.isSelfIssued()) {
            result--
        }

        val constraints =
            currentCert.findExtension(KnownOIDs.policyConstraints)?.decodePolicyConstraints()
                ?: return result

        val inhibitMapping = constraints.inhibitPolicyMapping.toBigInteger().intValue()
        if (inhibitMapping != -1 && (result == -1 || inhibitMapping < result)) {
            result = inhibitMapping
        }

        return result
    }


    private fun mergeInhibitAnyPolicy(
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

        if (policyExtension != null && root != null) {
            isCritical = policyExtension.critical
            val policies = policyExtension.decodeCertificatePolicies()

            var containsAnyPolicy = false

            for (policyInfo in policies) {
                val policyOid = policyInfo.oid

                if (policyOid == KnownOIDs.anyPolicy) {
                    containsAnyPolicy = true
                    anyPolicyQualifiers.addAll(policyInfo.policyQualifiers)
                    continue
                }

                val qualifiers = policyInfo.policyQualifiers
                if (qualifiers.isNotEmpty() && rejectPolicyQualifiers && isCritical) {
                    throw Exception("Critical policy qualifiers present in certificate")
                }

                val matched = processParentNodes(
                    certIndex,
                    isCritical,
                    rejectPolicyQualifiers,
                    root,
                    policyOid,
                    qualifiers,
                    matchAnyPolicy = false
                )

                if (!matched) {
                    processParentNodes(
                        certIndex,
                        isCritical,
                        rejectPolicyQualifiers,
                        root,
                        policyOid,
                        qualifiers,
                        matchAnyPolicy = true
                    )
                }
            }

            if (containsAnyPolicy) {
                if (inhibitAnyPolicy > 0 || (!isFinalCert && currentCert.isSelfIssued())) {
                    processParentNodes(
                        certIndex,
                        isCritical,
                        rejectPolicyQualifiers,
                        root,
                        KnownOIDs.anyPolicy,
                        anyPolicyQualifiers,
                        matchAnyPolicy = true
                    )
                }
            }

            root.prune(certIndex)
            if (root.children.isEmpty()) root = null
        } else if (policyExtension == null) {
            root = null
        }

        if (root != null && !isFinalCert) {
            root = processPolicyMappings(
                currentCert, certIndex, policyMapping, root, isCritical, anyPolicyQualifiers
            )
        }

        if (root != null && !initialPolicies.contains(KnownOIDs.anyPolicy)) {
            root = policyExtension?.let {
                removeInvalidNodes(root!!, certIndex, initialPolicies, it)
            }

            if (root != null && isFinalCert) {
                root = rewriteLeafNodes(certIndex, initialPolicies, root)
            }
        }

        if (isFinalCert) {
            val remainingExplicit = mergeExplicitPolicy(explicitPolicy, currentCert, true)
            if (remainingExplicit == 0 && root == null) {
                throw Exception("Non-null policy tree required but policy tree is null")
            }
        }

        return root
    }


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

    private fun processParentNodes(
        certIndex: Int,
        isCritical: Boolean,
        rejectQualifiers: Boolean,
        root: PolicyNode,
        currentPolicy: ObjectIdentifier,
        qualifiers: Set<PolicyQualifierInfo>,
        matchAnyPolicy: Boolean
    ): Boolean {
        val parentNodes = root.getPolicyNodesExpected(certIndex - 1, currentPolicy, matchAnyPolicy)
        if (parentNodes.isEmpty()) return false

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
            }
        }

        return true
    }

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

    fun getPolicyTree(): PolicyNode? {
        return rootNode?.copyTree()?.apply {
            isImmutable = true
        }
    }
}