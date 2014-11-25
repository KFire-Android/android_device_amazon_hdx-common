BOARD_VENDOR := amazon

# headers
TARGET_SPECIFIC_HEADER_PATH := device/amazon/hdx-common/include

# Platform
TARGET_BOARD_PLATFORM := msm8974
TARGET_BOARD_PLATFORM_GPU := qcom-adreno330
TARGET_BOOTLOADER_BOARD_NAME := MSM8974

# Bootloader
TARGET_NO_BOOTLOADER := true

# Architecture
TARGET_ARCH := arm
TARGET_CPU_ABI := armeabi-v7a
TARGET_CPU_ABI2 := armeabi
TARGET_CPU_SMP := true
TARGET_ARCH_VARIANT := armv7-a-neon
TARGET_CPU_VARIANT := krait
# Kernel
BOARD_KERNEL_CMDLINE := console=ttyHSL0,115200,n8 androidboot.hardware=qcom androidboot.baseband=apq user_debug=31 maxcpus=2 msm_rtb.filter=0x3F ehci-hcd.park=3 androidboot.selinux=permissive
BOARD_KERNEL_BASE := 0x00000000
BOARD_KERNEL_PAGESIZE := 2048
BOARD_MKBOOTIMG_ARGS := --ramdisk_offset 0x02000000 --tags_offset 0x01e00000
BOARD_KERNEL_SEPARATED_DT := true
# Kernel Configs
TARGET_KERNEL_SOURCE := kernel/qcom/msm8974
#kernel/amazon/hdx-common
TARGET_KERNEL_SELINUX_CONFIG := selinux_defconfig
# Flags for Krait CPU
TARGET_GLOBAL_CFLAGS += -mfpu=neon-vfpv4 -mfloat-abi=softfp
TARGET_GLOBAL_CPPFLAGS += -mfpu=neon-vfpv4 -mfloat-abi=softfp
# Flags
COMMON_GLOBAL_CFLAGS += -DQCOM_HARDWARE -DAMZ_HDX
# -DDUAL_DSI <- NO !
#COMMON_GLOBAL_CFLAGS += -DQCOM_BSP -DNEEDS_VECTORIMPL_SYMBOLS
COMMON_GLOBAL_CFLAGS += -DNO_SECURE_DISCARD

# QCOM hardware
BOARD_USES_QCOM_HARDWARE := true
TARGET_USES_QCOM_BSP := true
TARGET_ENABLE_QC_AV_ENHANCEMENTS := true
TARGET_QCOM_AUDIO_VARIANT := caf-hdx
TARGET_QCOM_DISPLAY_VARIANT := caf-hdx
TARGET_QCOM_MEDIA_VARIANT := caf-hdx

# Audio
AUDIO_FEATURE_DISABLED_SSR := true #MSM ANDROID
BOARD_USES_ALSA_AUDIO := true
BOARD_USES_LEGACY_ALSA_AUDIO := false

# Bluetooth
BOARD_HAVE_BLUETOOTH := true
BOARD_HAVE_BLUETOOTH_QCOM := true

# chargers
BOARD_CHARGER_RES := device/amazon/hdx-common/charger

# Graphics
#TARGET_DISPLAY_USE_RETIRE_FENCE := true
BOARD_EGL_CFG := device/amazon/hdx-common/egl.cfg
USE_OPENGL_RENDERER := true
TARGET_USES_C2D_COMPOSITION := true
TARGET_USES_ION := true
#OVERRIDE_RS_DRIVER := libRSDriver_adreno.so
#HAVE_ADRENO_SOURCE:= false
#VSYNC_EVENT_PHASE_OFFSET_NS := 7500000
#SF_VSYNC_EVENT_PHASE_OFFSET_NS := 5000000
#MAX_EGL_CACHE_KEY_SIZE := 12*1024
#MAX_EGL_CACHE_SIZE := 2048*1024

# Webkit
ENABLE_WEBGL := true
TARGET_FORCE_CPU_UPLOAD := true

# Charging mode
BOARD_CHARGING_MODE_BOOTING_LPM := 
BOARD_BATTERY_DEVICE_NAME := "bq27x41"

# Wifi related defines
WIFI_BAND := 802_11_ABG
WPA_SUPPLICANT_VERSION := VER_0_8_X
BOARD_WPA_SUPPLICANT_DRIVER := NL80211
BOARD_HOSTAPD_DRIVER := NL80211

# ATH6KL WLAN
BOARD_WLAN_DEVICE := qcwcn
BOARD_HAS_QCOM_WLAN := true
TARGET_USES_WCNSS_CTRL := true
WIFI_DRIVER_FW_PATH_STA := "sta"
WIFI_DRIVER_FW_PATH_AP := "ap"
BOARD_WPA_SUPPLICANT_PRIVATE_LIB := lib_driver_cmd_$(BOARD_WLAN_DEVICE)
BOARD_HOSTAPD_PRIVATE_LIB := lib_driver_cmd_$(BOARD_WLAN_DEVICE)

# NFC
BOARD_HAVE_NFC := false

# Vold
BOARD_VOLD_EMMC_SHARES_DEV_MAJOR := true
BOARD_VOLD_MAX_PARTITIONS := 32
TARGET_USE_CUSTOM_LUN_FILE_PATH := /sys/devices/platform/msm_hsusb/gadget/lun%d/file

# custom liblights (because we basically have none)
TARGET_PROVIDES_LIBLIGHT := true

# Temporary
USE_CAMERA_STUB := true

# Recovery
TARGET_RECOVERY_PIXEL_FORMAT := "RGBX_8888"
BOARD_USES_MMCUTILS := true
BOARD_HAS_LARGE_FILESYSTEM := true
BOARD_HAS_NO_MISC_PARTITION := true
BOARD_HAS_NO_SELECT_BUTTON := true
TARGET_RECOVERY_FSTAB := device/amazon/hdx-common/rootdir/etc/fstab.qcom

# TWRP
RECOVERY_GRAPHICS_USE_LINELENGTH := true
RECOVERY_SDCARD_ON_DATA := true
TW_EXTERNAL_STORAGE_PATH := "/external_sd"
TW_EXTERNAL_STORAGE_MOUNT_POINT := "external_sd"
TARGET_USERIMAGES_USE_EXT4 := true
TW_BRIGHTNESS_PATH := /sys/class/leds/lcd-backlight/brightness
TW_CUSTOM_BATTERY_PATH := /sys/class/power_supply/bq27x41

TARGET_USERIMAGES_USE_EXT4 := true
BOARD_BOOTIMAGE_PARTITION_SIZE := 10485760
BOARD_RECOVERYIMAGE_PARTITION_SIZE := 10485760
BOARD_SYSTEMIMAGE_PARTITION_SIZE := 1308622848
BOARD_USERDATAIMAGE_PARTITION_SIZE := 12549340160
BOARD_FLASH_BLOCK_SIZE := 131072
