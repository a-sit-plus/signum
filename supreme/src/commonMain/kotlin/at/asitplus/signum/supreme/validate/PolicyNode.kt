package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.supreme.validate.pkiExtensions.PolicyQualifierInfo

class PolicyNode(
    val parent: PolicyNode?,
    val validPolicy: ObjectIdentifier,
    qualifierSet: Set<PolicyQualifierInfo> = emptySet(),
    val criticalityIndicator: Boolean,
    expectedPolicySet: Set<ObjectIdentifier> = emptySet(),
    generatedByPolicyMapping: Boolean
) {
    val children = mutableSetOf<PolicyNode>()
    val qualifierSet: MutableSet<PolicyQualifierInfo> = qualifierSet.toMutableSet()
    val expectedPolicySet: MutableSet<ObjectIdentifier> = expectedPolicySet.toMutableSet()
    private var originalExpectedPolicySet = !generatedByPolicyMapping
    private val depth: Int = (parent?.depth ?: -1) + 1
    var isImmutable: Boolean = false
        private set

    init {
        parent?.addChild(this)
    }

    private fun addChild(child: PolicyNode) {
        children += child
    }

    constructor(
        parent: PolicyNode?,
        validPolicy: String?,
        qualifierSet: Set<PolicyQualifierInfo>?,
        criticalityIndicator: Boolean,
        expectedPolicySet: Set<String>?,
        generatedByPolicyMapping: Boolean
    ) : this(
        parent = parent,
        validPolicy = ObjectIdentifier(validPolicy ?: ""),
        qualifierSet = qualifierSet ?: emptySet(),
        criticalityIndicator = criticalityIndicator,
        expectedPolicySet = expectedPolicySet?.map { ObjectIdentifier(it) }?.toSet() ?: emptySet(),
        generatedByPolicyMapping = generatedByPolicyMapping
    )

    constructor(parent: PolicyNode?, node: PolicyNode) : this(
        parent = parent,
        validPolicy = node.validPolicy,
        qualifierSet = node.qualifierSet,
        criticalityIndicator = node.criticalityIndicator,
        expectedPolicySet = node.expectedPolicySet,
        generatedByPolicyMapping = false
    )

    fun addExpectedPolicy(expectedPolicy: ObjectIdentifier) {
        check(!isImmutable) { "PolicyNode is immutable" }
        if (originalExpectedPolicySet) {
            expectedPolicySet.clear()
            originalExpectedPolicySet = false
        }
        expectedPolicySet += expectedPolicy
    }

    fun prune(minDepth: Int) {
        check(!isImmutable) { "PolicyNode is immutable" }

        if (children.isEmpty()) return

        val it = children.iterator()
        while (it.hasNext()) {
            val node = it.next()
            node.prune(minDepth)
            if (node.children.isEmpty() && minDepth > this.depth + 1) {
                it.remove()
            }
        }
    }

    fun deleteChild(child: PolicyNode) {
        check(!isImmutable) { "PolicyNode is immutable" }
        children -= child
    }

    fun copyTree(): PolicyNode = copyTreeInternal(null)

    private fun copyTreeInternal(parent: PolicyNode?): PolicyNode =
        PolicyNode(parent, this).also { newNode ->
            children.forEach { it.copyTreeInternal(newNode) }
        }

    fun getPolicyNodes(targetDepth: Int): Set<PolicyNode> =
        buildSet { getPolicyNodes(targetDepth, this) }

    private fun getPolicyNodes(targetDepth: Int, acc: MutableSet<PolicyNode>) {
        if (depth == targetDepth) {
            acc += this
        } else {
            children.forEach { it.getPolicyNodes(targetDepth, acc) }
        }
    }

    fun getPolicyNodesExpected(
        depth: Int,
        expectedOID: ObjectIdentifier,
        matchAny: Boolean
    ): Set<PolicyNode> = if (expectedOID == KnownOIDs.anyPolicy) {
        getPolicyNodes(depth)
    } else {
        getPolicyNodesExpectedHelper(depth, expectedOID, matchAny)
    }

    private fun getPolicyNodesExpectedHelper(
        depth: Int,
        expectedOID: ObjectIdentifier,
        matchAny: Boolean
    ): Set<PolicyNode> = buildSet {
        if (this@PolicyNode.depth < depth) {
            children.forEach {
                addAll(it.getPolicyNodesExpectedHelper(depth, expectedOID, matchAny))
            }
        } else {
            if (
                (matchAny && KnownOIDs.anyPolicy in expectedPolicySet) ||
                (!matchAny && expectedOID in expectedPolicySet)
            ) {
                add(this@PolicyNode)
            }
        }
    }

    fun getPolicyNodesValid(depth: Int, validOID: ObjectIdentifier): Set<PolicyNode> =
        buildSet {
            if (this@PolicyNode.depth < depth) {
                children.forEach { addAll(it.getPolicyNodesValid(depth, validOID)) }
            } else if (validPolicy == validOID) {
                add(this@PolicyNode)
            }
        }
}

