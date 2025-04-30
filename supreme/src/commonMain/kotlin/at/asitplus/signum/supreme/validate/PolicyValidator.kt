package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.pki.X509Certificate

class PolicyValidator(
    initialPolicies: Set<String>,
    private val certPathLen: Int,
    private val expPolicyRequired: Boolean,
    private val polMappingInhibited: Boolean,
    private val anyPolicyInhibited: Boolean,
    private val rejectPolicyQualifiers: Boolean,
    private var rootNode: PolicyNode
) {
    private val initPolicies: Set<String> = if (initialPolicies.isEmpty()) {
        setOf(ANY_POLICY)
    } else {
        initialPolicies.toSet()
    }
    private var explicitPolicy: Int = 0
    private var policyMapping: Int = 0
    private var inhibitAnyPolicy: Int = 0
    private var certIndex: Int = 0

    private var supportedExtensions: Set<String>? = null

    companion object {
        val ANY_POLICY = KnownOIDs.anyPolicy.toString()
    }

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

//    private fun checkPolicy(currCert: X509Certificate) {
//
//        val finalCert = certIndex == certPathLen
//
//        rootNode = processPolicies(
//            certIndex,
//            initPolicies,
//            explicitPolicy,
//            policyMapping,
//            inhibitAnyPolicy,
//            rejectPolicyQualifiers,
//            rootNode,
//            currCertImpl,
//            finalCert
//        )
//
//        if (!finalCert) {
//            explicitPolicy = mergeExplicitPolicy(explicitPolicy, currCertImpl, false)
//            policyMapping = mergePolicyMapping(policyMapping, currCertImpl)
//            inhibitAnyPolicy = mergeInhibitAnyPolicy(inhibitAnyPolicy, currCertImpl)
//        }
//
//        certIndex++
//    }

    fun mergeExplicitPolicy(
        explicitPolicy: Int,
        currCert: X509Certificate,
        finalCert: Boolean
    ): Int {
        var result = explicitPolicy
//        TODO consider transfer is self issued logic into X509Certificate
        if (result > 0 && currCert.tbsCertificate.subjectName!=currCert.tbsCertificate.issuerName) {
            result--
        }

        return result
//        TODO create policyConstrainExtension class or just extract require flag from the constraint
//        val polConstExt = currCert.policyConstraintsExtension ?: return result
//        val require = polConstExt.require
//
//        if (!finalCert) {
//            if (require != -1) {
//                if (result == -1 || require < result) {
//                    result = require
//                }
//            }
//        } else {
//            if (require == 0) {
//                result = require
//            }
//        }
//
//        return result
    }

    fun mergePolicyMapping(policyMapping: Int, currCert: X509Certificate): Int {
        var updatedMapping = policyMapping

        if (updatedMapping > 0 && currCert.tbsCertificate.subjectName!=currCert.tbsCertificate.issuerName) {
            updatedMapping--
        }

//        TODO create policyConstrainExtension class or just extract inhibit flag from the constraint
//        val polConstExt = currCert.policyConstraintsExtension ?: return updatedMapping
//
//        val inhibit = polConstExt.inhibit
//        debug?.println("PolicyChecker.mergePolicyMapping() inhibit Index from cert = $inhibit")
//
//        if (inhibit != -1) {
//            if (updatedMapping == -1 || inhibit < updatedMapping) {
//                updatedMapping = inhibit
//            }
//        }

        return updatedMapping
    }

    fun mergeInhibitAnyPolicy(inhibitAnyPolicy: Int, currCert: X509Certificate): Int {
        var updatedInhibitAnyPolicy = inhibitAnyPolicy

        if (updatedInhibitAnyPolicy > 0 && currCert.tbsCertificate.subjectName!=currCert.tbsCertificate.issuerName) {
            updatedInhibitAnyPolicy--
        }

//        TODO create InhibitAnyPolicyExtension
//        val inhAnyPolExt = currCert.getExtension(KnownOIDs.inhibitAnyPolicy) as? InhibitAnyPolicyExtension
//            ?: return updatedInhibitAnyPolicy
//
//        val skipCerts = inhAnyPolExt.skipCerts
//        debug?.println("PolicyChecker.mergeInhibitAnyPolicy() skipCerts Index from cert = $skipCerts")
//
//        if (skipCerts != -1 && skipCerts < updatedInhibitAnyPolicy) {
//            updatedInhibitAnyPolicy = skipCerts
//        }

        return updatedInhibitAnyPolicy
    }

    fun processPolicies(
        certIndex: Int,
        initPolicies: Set<String>,
        explicitPolicy: Int,
        policyMapping: Int,
        inhibitAnyPolicy: Int,
        rejectPolicyQualifiers: Boolean,
        origRootNode: PolicyNode?,
        currCert: X509Certificate,
        finalCert: Boolean
    ): PolicyNode? {
        var policiesCritical = false
        val anyQuals = mutableSetOf<String>()
        var rootNode: PolicyNode? = origRootNode?.copyTree()

        val currCertPolicies = currCert.getCertificatePoliciesExtension()

        if (currCertPolicies != null && rootNode != null) {
            policiesCritical = currCertPolicies.isCritical

            val policyInfo = currCertPolicies.certPolicies

            var foundAnyPolicy = false

            for (curPolInfo in policyInfo) {
                val curPolicy = curPolInfo.policyIdentifier.identifier.toString()

                if (curPolicy == ANY_POLICY) {
                    foundAnyPolicy = true
                    anyQuals.addAll(curPolInfo.policyQualifiers)
                } else {

                    val pQuals = curPolInfo.policyQualifiers

                    if (pQuals.isNotEmpty() && rejectPolicyQualifiers && policiesCritical) {
                        throw Exception(
                            "critical policy qualifiers present in certificate",
                        )
                    }

                    val foundMatch = processParents(
                        certIndex, policiesCritical, rejectPolicyQualifiers,
                        rootNode, curPolicy, pQuals, false
                    )

                    if (!foundMatch) {
                        processParents(
                            certIndex, policiesCritical, rejectPolicyQualifiers,
                            rootNode, curPolicy, pQuals, true
                        )
                    }
                }
            }

            if (foundAnyPolicy) {
                if (inhibitAnyPolicy > 0 || (!finalCert && currCert.tbsCertificate.subjectName==currCert.tbsCertificate.issuerName)) {
                    processParents(
                        certIndex, policiesCritical, rejectPolicyQualifiers,
                        rootNode, ANY_POLICY, anyQuals, true
                    )
                }
            }

            rootNode.prune(certIndex)
            if (rootNode.children.hasNext() == false) {
                rootNode = null
            }
        } else if (currCertPolicies == null) {
            rootNode = null
        }

        if (rootNode != null && !finalCert) {
            rootNode = processPolicyMappings(
                currCert, certIndex, policyMapping,
                rootNode, policiesCritical, anyQuals
            )
        }

        if (rootNode != null && !initPolicies.contains(ANY_POLICY)) {
            rootNode = removeInvalidNodes(rootNode, certIndex, initPolicies, currCertPolicies)

            if (rootNode != null && finalCert) {
                rootNode = rewriteLeafNodes(certIndex, initPolicies, rootNode)
            }
        }

        if (finalCert) {
            mergeExplicitPolicy(explicitPolicy, currCert, true).also {
                if (it == 0 && rootNode == null) {
                    throw Exception(
                        "non-null policy tree required and policy tree is null",
                    )
                }
            }
        }

        return rootNode
    }

    private fun rewriteLeafNodes(
        certIndex: Int,
        initPolicies: Set<String>,
        rootNode: PolicyNode
    ): PolicyNode? {
        val anyNodes = rootNode.getPolicyNodesValid(certIndex, ANY_POLICY)
        if (anyNodes.isEmpty()) {
            return rootNode
        }

        val anyNode = anyNodes.iterator().next()
        val parentNode = anyNode.parent as PolicyNode
        parentNode.deleteChild(anyNode)

        val initial = initPolicies.toMutableSet()
        for (node in rootNode.getPolicyNodes(certIndex)) {
            initial.remove(node.validPolicy)
        }

        return if (initial.isEmpty()) {
            rootNode.prune(certIndex)
            if (rootNode.children.isNotEmpty()) {
                null
            } else {
                rootNode
            }
        } else {
            val anyCritical = anyNode.criticalityIndicator
            val anyQualifiers = anyNode.qualifierSet
            for (policy in initial) {
                val expectedPolicies = setOf(policy)
                PolicyNode(
                    parentNode, policy,
                    anyQualifiers, anyCritical, expectedPolicies, false
                )
            }
            rootNode
        }
    }

    private fun processParents(
        certIndex: Int,
        policiesCritical: Boolean,
        rejectPolicyQualifiers: Boolean,
        rootNode: PolicyNode,
        curPolicy: String,
        pQuals: Set<String>,
        matchAny: Boolean
    ): Boolean {
        var foundMatch = false


        val parentNodes = rootNode.getPolicyNodesExpected(certIndex - 1, curPolicy, matchAny)

        for (curParent in parentNodes) {
            foundMatch = true

            if (curPolicy == ANY_POLICY) {
                val parExpPols = curParent.expectedPolicySet
                parentExplicitPolicies@ for (curParExpPol in parExpPols) {
                    for (childNode in curParent.children) {
                        if (curParExpPol == childNode.validPolicy) {
                            continue@parentExplicitPolicies
                        }
                    }

                    val expPols = mutableSetOf(curParExpPol)
                    PolicyNode(
                        curParent, curParExpPol, pQuals,
                        policiesCritical, expPols, false
                    )
                }
            } else {
                val curExpPols = mutableSetOf(curPolicy)
                PolicyNode(
                    curParent, curPolicy, pQuals,
                    policiesCritical, curExpPols, false
                )
            }
        }

        return foundMatch
    }

    private fun processPolicyMappings(
        currCert: X509Certificate,
        certIndex: Int,
        policyMapping: Int,
        rootNode: PolicyNode,
        policiesCritical: Boolean,
        anyQuals: Set<String>
    ): PolicyNode? {
        val polMappingsExt = currCert.getPolicyMappingsExtension() ?: return rootNode

        val maps = polMappingsExt.maps
        var childDeleted = false

        for (polMap in maps) {
            val issuerDomain = polMap.issuerIdentifier.identifier.toString()
            val subjectDomain = polMap.subjectIdentifier.identifier.toString()

            if (issuerDomain == ANY_POLICY) {
                throw Exception(
                    "encountered an issuerDomainPolicy of ANY_POLICY"
                )
            }

            if (subjectDomain == ANY_POLICY) {
                throw Exception(
                    "encountered a subjectDomainPolicy of ANY_POLICY"
                )
            }

            val validNodes = rootNode.getPolicyNodesValid(certIndex, issuerDomain)
            if (validNodes.isNotEmpty()) {
                for (curNode in validNodes) {
                    when {
                        policyMapping > 0 || policyMapping == -1 -> {
                            curNode.addExpectedPolicy(subjectDomain)
                        }
                        policyMapping == 0 -> {
                            val parentNode = curNode.parent as PolicyNode
                            parentNode.deleteChild(curNode)
                            childDeleted = true
                        }
                    }
                }
            } else {
                if (policyMapping > 0 || policyMapping == -1) {
                    val validAnyNodes = rootNode.getPolicyNodesValid(certIndex, ANY_POLICY)
                    for (curAnyNode in validAnyNodes) {
                        val curAnyNodeParent = curAnyNode.parent as PolicyNode
                        val expPols = setOf(subjectDomain)

                        PolicyNode(
                            curAnyNodeParent, issuerDomain, anyQuals,
                            policiesCritical, expPols, true
                        )
                    }
                }
            }
        }
        if (childDeleted) {
            rootNode.prune(certIndex)
            if (rootNode.children.isEmpty()) {
                return null
            }
        }
        return rootNode
    }

    private fun removeInvalidNodes(
        rootNode: PolicyNode,
        certIndex: Int,
        initPolicies: Set<String>,
        currCertPolicies: CertificatePoliciesExtension
    ): PolicyNode? {
        val policyInfo = currCertPolicies.certPolicies
        var childDeleted = false

        for (curPolInfo in policyInfo) {
            val curPolicy = curPolInfo.policyIdentifier.identifier.toString()

            val validNodes = rootNode.getPolicyNodesValid(certIndex, curPolicy)
            for (curNode in validNodes) {
                val parentNode = curNode.parent as PolicyNode
                if (parentNode.validPolicy == ANY_POLICY) {
                    if (curPolicy != ANY_POLICY && curPolicy !in initPolicies) {
                        parentNode.deleteChild(curNode)
                        childDeleted = true
                    }
                }
            }
        }

        if (childDeleted) {
            rootNode.prune(certIndex)
            if (rootNode.children.isEmpty()) {
                return null
            }
        }

        return rootNode
    }

    fun getPolicyTree(): PolicyNode? {
        return rootNode.copyTree().apply {
            isImmutable = true
        }
    }
}