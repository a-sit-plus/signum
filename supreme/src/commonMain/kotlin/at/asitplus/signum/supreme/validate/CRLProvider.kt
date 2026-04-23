package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.deltaCRLIndicator
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.CertificateList
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.pkiExtensions.CRLDistributionPointsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.IssuingDistributionPointExtension
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.buffered
import kotlinx.io.files.FileSystem
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray

/**
 * Fetches Certificate Revocation Lists
 */
interface CRLProvider {
    /**
     * Attempts to find a valid CRL for the given issuer.
     */
    suspend fun fetchCRLs(targetCert: X509Certificate, issuerCert: X509Certificate): List<CertificateList>

    /**
     * Fetch CRLs from CRL Distribution Points (CDP extension).
     */
    suspend fun fetchCRLsFromDistributionPoints(cert: X509Certificate): List<CertificateList>

    /**
     * Fetch Delta CRLs associated with a specific Base CRL.
     */
    suspend fun fetchDeltaCRLs(baseCrl: CertificateList, targetCert: X509Certificate): List<CertificateList>
}


@ExperimentalPkiApi
object SystemCRLCache {
    private val mutex = Mutex()
    private var _cache: List<CertificateList>? = null

    /**
     * Provides the cache. Throws if accessed before [initialize] is called.
     */
    val crls: List<CertificateList>
        get() = _cache ?: throw IllegalStateException("SystemCrlCache not initialized. Call initialize() first.")


    suspend fun initialize(path: String, fileSystem: FileSystem = SystemFileSystem) {
        if (_cache != null) return
        mutex.withLock {
            if (_cache == null) {
                val provider = DirectoryCRLProvider.create(path, fileSystem)
                _cache = provider.crlCache
            }
        }
    }
}

/**
 * A provider that loads and caches all CRLs from a specific local directory
 */
class DirectoryCRLProvider @OptIn(ExperimentalPkiApi::class) constructor(
    val crlCache: List<CertificateList> = SystemCRLCache.crls
) : CRLProvider {

    /**
     * Finds the CRL issued by the [issuerCert].
     */
    @OptIn(ExperimentalPkiApi::class)
    override suspend fun fetchCRLs(targetCert: X509Certificate, issuerCert: X509Certificate): List<CertificateList> {
        val issuerName = issuerCert.tbsCertificate.subjectName

        return crlCache.filter { crl ->
                crl.tbsCertList.issuer.constrains(issuerName) == GeneralNameOption.ConstraintResult.MATCH
            }
    }

    companion object {
        suspend fun create(
            folderPath: String,
            fileSystem: FileSystem = SystemFileSystem
        ): DirectoryCRLProvider = withContext(Dispatchers.Default) {
            val cache = mutableListOf<CertificateList>()
            val rootPath = Path(folderPath)

            if (!fileSystem.exists(rootPath)) {
                return@withContext DirectoryCRLProvider(emptyList())
            }

            fileSystem.list(rootPath).forEach { filePath ->
                if (filePath.name.endsWith(".crl", ignoreCase = true)) {
                    runCatching {
                        val bytes = fileSystem.source(filePath).buffered().use { it.readByteArray() }
                        val src = Asn1Element.parse(bytes) as Asn1Sequence
                        val crl = CertificateList.decodeFromTlv(src)
                        cache.add(crl)
                    }.onFailure {
                        println("Failed to load CRL at ${filePath.name}: ${it.message}")
                    }
                }
            }
            DirectoryCRLProvider(cache)
        }
    }

    override suspend fun fetchCRLsFromDistributionPoints(
        cert: X509Certificate
    ): List<CertificateList> {
        val cdpExt = cert.findExtension<CRLDistributionPointsExtension>() ?: return emptyList()

        return cdpExt.distributionPoints.flatMap { dp ->
            val dpName = dp.distributionPointName
            val currentCrlIssuers = dp.crlIssuer

            crlCache.filter { crl ->
                val idp = crl.findExtension<IssuingDistributionPointExtension>()
                val idpName = idp?.distributionPointName

                if (!currentCrlIssuers.isNullOrEmpty()) {
                    val isAuthorized = currentCrlIssuers.any { it.name == crl.tbsCertList.issuer }

                    if (!isAuthorized || idp?.indirectCRL != true) {
                        return@filter false
                    }

                    return@filter if (dpName != null && idpName != null) {
                        matchesDistributionPointNames(
                            idpName = idpName,
                            idpBase = crl.tbsCertList.issuer,
                            cdpName = dpName,
                            cdpBase = crl.tbsCertList.issuer
                        )
                    } else {
                        true
                    }
                }

                if (crl.tbsCertList.issuer != cert.tbsCertificate.issuerName) {
                    return@filter false
                }

                return@filter when {
                    dpName != null && idpName != null -> matchesDistributionPointNames(
                        idpName = idpName,
                        idpBase = crl.tbsCertList.issuer,
                        cdpName = dpName,
                        cdpBase = cert.tbsCertificate.issuerName
                    )
                    else -> true
                }
            }
        }.distinct()
    }

    override suspend fun fetchDeltaCRLs(
        baseCrl: CertificateList,
        targetCert: X509Certificate
    ): List<CertificateList> {
        val baseIssuer = baseCrl.tbsCertList.issuer
        val baseIdp = baseCrl.findExtension<IssuingDistributionPointExtension>()

        return crlCache.filter { crl ->
            if (crl.tbsCertList.issuer != baseIssuer) return@filter false

            val isDelta = crl.tbsCertList.extensions?.any { it.oid == KnownOIDs.deltaCRLIndicator } == true
            if (!isDelta) return@filter false

            val deltaIdp = crl.findExtension<IssuingDistributionPointExtension>()
            deltaIdp == baseIdp
        }
    }
}