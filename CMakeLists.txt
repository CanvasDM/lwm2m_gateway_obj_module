#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#

if(CONFIG_LCZ_LWM2M_GATEWAY_OBJ)

zephyr_include_directories(include)

zephyr_sources(src/lcz_lwm2m_gateway_obj.c)

endif()
