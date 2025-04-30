package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.asn1.KnownOIDs

class PolicyNode(
    val parent: PolicyNode?,
    val validPolicy: String,
    qualifierSet: Set<String>?,
    val criticalityIndicator: Boolean,
    expectedPolicySet: Set<String>?,
    generatedByPolicyMapping: Boolean
) {

    companion object {
        val ANY_POLICY = KnownOIDs.anyPolicy.toString()
    }

    val children: MutableSet<PolicyNode> = mutableSetOf()

    val qualifierSet: MutableSet<String> =
        qualifierSet?.toMutableSet() ?: mutableSetOf()

    val expectedPolicySet: MutableSet<String> =
        expectedPolicySet?.toMutableSet() ?: mutableSetOf()

    val actualValidPolicy: String = validPolicy.ifEmpty { "" }

    var originalExpectedPolicySet: Boolean = !generatedByPolicyMapping
        private set

    val depth: Int

    var isImmutable: Boolean = false

    init {
        depth = parent?.let {
            it.addChild(this)
            it.depth + 1
        } ?: 0
    }

    private fun addChild(child: PolicyNode) {
        children.add(child)
    }

    constructor(parent: PolicyNode?, node: PolicyNode) : this(
        parent = parent,
        validPolicy = node.validPolicy,
        qualifierSet = node.qualifierSet,
        criticalityIndicator = node.criticalityIndicator,
        expectedPolicySet = node.expectedPolicySet,
        generatedByPolicyMapping = false
    )

    fun addExpectedPolicy(expectedPolicy: String) {
        if (isImmutable) throw IllegalStateException("PolicyNode is immutable")
        if (originalExpectedPolicySet) {
            expectedPolicySet.clear()
            originalExpectedPolicySet = false
        }
        expectedPolicySet.add(expectedPolicy)
    }

    fun prune(minDepth: Int) {
        if (isImmutable) throw IllegalStateException("PolicyNode is immutable")

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

    fun deleteChild(childNode: PolicyNode) {
        if (isImmutable) throw IllegalStateException("PolicyNode is immutable")
        children.remove(childNode)
    }

    fun copyTree(): PolicyNode = copyTreeInternal(null)

    private fun copyTreeInternal(parent: PolicyNode?): PolicyNode {
        val newNode = PolicyNode(parent, this)
        children.forEach { it.copyTreeInternal(newNode) }
        return newNode
    }

    fun getPolicyNodes(targetDepth: Int): Set<PolicyNode> {
        val set = mutableSetOf<PolicyNode>()
        getPolicyNodes(targetDepth, set)
        return set
    }

    private fun getPolicyNodes(targetDepth: Int, set: MutableSet<PolicyNode>) {
        if (this.depth == targetDepth) {
            set.add(this)
        } else {
            children.forEach { it.getPolicyNodes(targetDepth, set) }
        }
    }

    fun getPolicyNodesExpected(depth: Int, expectedOID: String, matchAny: Boolean): Set<PolicyNode> {
        return if (expectedOID == ANY_POLICY) {
            getPolicyNodes(depth)
        } else {
            getPolicyNodesExpectedHelper(depth, expectedOID, matchAny)
        }
    }

    private fun getPolicyNodesExpectedHelper(depth: Int, expectedOID: String, matchAny: Boolean): Set<PolicyNode> {
        val set = mutableSetOf<PolicyNode>()
        if (this.depth < depth) {
            children.forEach { set.addAll(it.getPolicyNodesExpectedHelper(depth, expectedOID, matchAny)) }
        } else {
            if ((matchAny && expectedPolicySet.contains(ANY_POLICY)) ||
                (!matchAny && expectedPolicySet.contains(expectedOID))) {
                set.add(this)
            }
        }
        return set
    }

    fun getPolicyNodesValid(depth: Int, validOID: String): Set<PolicyNode> {
        val set = mutableSetOf<PolicyNode>()
        if (this.depth < depth) {
            children.forEach { set.addAll(it.getPolicyNodesValid(depth, validOID)) }
        } else if (this.validPolicy == validOID) {
            set.add(this)
        }
        return set
    }
}
