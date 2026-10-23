package com.dev.fido.bridge.client.transport.ble

import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.os.ParcelUuid
import android.util.Log
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.DecryptedBleAdvert
import java.util.UUID

// Resolve BluetoothLeScanner dynamically per session so toggling system Bluetooth does not leave a stale reference
class HybridBleScanner(private val scannerProvider: () -> BluetoothLeScanner?) {

    private val fidoServiceUuid = ParcelUuid(UUID.fromString("0000fff9-0000-1000-8000-00805f9b34fb"))
    private var activeCallback: ScanCallback? = null

    /**
     * Start low-latency BLE scanning for caBLE v2 service data (0xFFF9) and trial-decrypt incoming frames
     * against the 64-byte [eidKey] per PXP §5.4.1. Stop scanning immediately upon the first valid match.
     */
    @Synchronized
    fun startScanning(
        eidKey: ByteArray,
        onAdvertMatched: (DecryptedBleAdvert) -> Unit,
        onFailure: ((Int) -> Unit)? = null
    ): Boolean {
        stopScanning()

        val scanner = scannerProvider()
        if (scanner == null) {
            Log.e("HybridBleScanner", "BLE Scanner not available")
            return false
        }

        val filter = ScanFilter.Builder()
            .setServiceUuid(fidoServiceUuid)
            .build()

        // Use SCAN_MODE_LOW_LATENCY so the client detects the authenticator's proximity burst immediately
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult?) {
                val scanRecord = result?.scanRecord ?: return
                val serviceData = scanRecord.getServiceData(fidoServiceUuid) ?: return

                val decrypted = CryptoHelper.trialDecryptEid(eidKey, serviceData) ?: return

                // Stop BLE radio scanning under lock before invoking network connection on the critical path
                val wonRace = synchronized(this@HybridBleScanner) {
                    if (activeCallback === this) {
                        try {
                            scannerProvider()?.stopScan(this)
                        } catch (e: Exception) {
                            Log.w("HybridBleScanner", "Failed to stop scan after match", e)
                        }
                        activeCallback = null
                        true
                    } else {
                        false
                    }
                }

                if (wonRace) {
                    Log.d("HybridBleScanner", "Matched and decrypted caBLE v2 BLE advertisement")
                    onAdvertMatched(decrypted)
                }
            }

            override fun onScanFailed(errorCode: Int) {
                Log.e("HybridBleScanner", "BLE Scan failed with errorCode: $errorCode")
                val shouldNotify = synchronized(this@HybridBleScanner) {
                    if (activeCallback === this) {
                        activeCallback = null
                        true
                    } else {
                        false
                    }
                }
                if (shouldNotify) {
                    onFailure?.invoke(errorCode)
                }
            }
        }

        return try {
            scanner.startScan(listOf(filter), settings, callback)
            activeCallback = callback
            true
        } catch (e: SecurityException) {
            Log.e("HybridBleScanner", "SecurityException: Missing BLUETOOTH_SCAN permission", e)
            false
        } catch (e: Exception) {
            Log.e("HybridBleScanner", "Unexpected error starting BLE scan", e)
            false
        }
    }

    @Synchronized
    fun stopScanning() {
        val callback = activeCallback ?: return
        try {
            scannerProvider()?.stopScan(callback)
            Log.d("HybridBleScanner", "BLE Scanning stopped")
        } catch (e: Exception) {
            Log.w("HybridBleScanner", "Failed to stop BLE scanning", e)
        } finally {
            activeCallback = null
        }
    }
}