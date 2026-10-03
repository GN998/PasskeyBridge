package com.dev.fido.bridge.core.transport.ble

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

/**
 * Manage Bluetooth Low Energy (BLE) advertisements for FIDO caBLE v2 hybrid transport.
 *
 * Broadcast the FIDO Service UUID (0xFFF9) with dynamic Service Data payloads. Support both
 * 20-byte Ad-hoc EID advertisements (QR flows) and 15-byte State-assisted advertisements
 * (paired reconnection flows) per CTAP 2.3 §11.5.
 */
class HybridBleAdvertiser(private val advertiser: BluetoothLeAdvertiser?) {

    companion object {
        private const val TAG = "HybridBleAdvertiser"

        /**
         * Standard FIDO Alliance 16-bit Service UUID assigned for BLE transport (0xFFF9).
         */
        val FIDO_SERVICE_UUID: UUID = UUID.fromString("0000fff9-0000-1000-8000-00805f9b34fb")
    }

    private var activeCallback: AdvertiseCallback? = null

    /**
     * Check whether BLE advertising is currently active.
     */
    val isAdvertising: Boolean
        get() = activeCallback != null

    /**
     * Start BLE advertising using a structured [BleAdvertisingMode] descriptor.
     *
     * Stop any pre-existing advertising session before configuring new advertising parameters to prevent
     * resource leaks on Android Bluetooth stacks.
     *
     * @param mode Advertising mode encapsulating the validated binary payload and expected length.
     */
    fun startAdvertising(mode: BleAdvertisingMode) {
        if (advertiser == null) {
            Log.e(TAG, "Cannot start BLE advertising: BluetoothLeAdvertiser is null or disabled")
            return
        }

        // Stop active advertising to ensure fresh advertising data registration
        stopAdvertising()

        try {
            mode.validate()
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Aborting BLE advertising due to payload validation failure", e)
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(false)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(FIDO_SERVICE_UUID))
            .addServiceData(ParcelUuid(FIDO_SERVICE_UUID), mode.rawPayload)
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.d(TAG, "BLE advertising started successfully (${mode.rawPayload.size} bytes payload)")
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e(TAG, "BLE advertising failed with error code $errorCode")
                activeCallback = null
            }
        }
        activeCallback = callback

        try {
            advertiser.startAdvertising(settings, data, callback)
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException: Missing BLUETOOTH_ADVERTISE permission", e)
            activeCallback = null
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected failure during BLE advertiser invocation", e)
            activeCallback = null
        }
    }

    /**
     * Convenience overload to start BLE advertising directly with raw bytes.
     *
     * Automatically deduce the appropriate [BleAdvertisingMode] based on byte length.
     *
     * @param rawEid Raw 20-byte or 15-byte advertising payload.
     */
    fun startAdvertising(rawEid: ByteArray) {
        val mode = when (rawEid.size) {
            20 -> BleAdvertisingMode.AdHoc(rawEid)
            15 -> BleAdvertisingMode.StateAssisted(rawEid)
            else -> {
                Log.e(TAG, "Unsupported BLE payload length: ${rawEid.size} bytes. Defaulting to AdHoc fallback.")
                BleAdvertisingMode.AdHoc(rawEid)
            }
        }
        startAdvertising(mode)
    }

    /**
     * Stop active BLE advertising session and release system resources.
     */
    fun stopAdvertising() {
        val callback = activeCallback ?: return
        try {
            advertiser?.stopAdvertising(callback)
            Log.d(TAG, "BLE advertising stopped cleanly")
        } catch (e: Exception) {
            Log.w(TAG, "Error encountered while stopping BLE advertiser", e)
        } finally {
            activeCallback = null
        }
    }
}
