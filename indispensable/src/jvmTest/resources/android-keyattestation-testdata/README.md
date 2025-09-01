## Installing TestDPC

```shell
$ bash third_party/java_src/testdpc/build-and-install.sh
$ adb -s localhost:45681 shell dpm set-device-owner com.afwsamples.testdpc/.DeviceAdminReceiver
```

# Running the Attestation Collector app

```shell
$ blaze run //java/com/google/wireless/android/security/attestationverifier:RegenerateTestData
```
