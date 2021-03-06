/**
****************************************************************************************************
* @file SfRulesList.h
* @brief Security framework [SF] filter driver [D] blocking rules list
* @date Created Sep 24, 2014 12:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#include <uapi/linux/sf/core/SfCore.h>

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SF_STATUS AddFileRule( Uint64 inode );

/**
****************************************************************************************************
*
****************************************************************************************************
*/
Bool FileAccessRestricted( Uint64 inode );

/**
****************************************************************************************************
*
****************************************************************************************************
*/
void ClearFileRulesList( void );