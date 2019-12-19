# @summary Entry point for Security Team's CIS module.
#
# This module enforces CIS benchmark settings for Windows 2019 and Centos 8 servers. There is a single parameter to optionally set noop mode for the scope of this class.
#
# @example
#   include secteam::profile
class secteam::profile (
  Boolean $secteam_noop = false,
){

  if $::secteam_noop == true {
    noop()
  }

  case $::osfamily {
    'Windows': {
      case $::os_major_family {
        '2019': {
          include secteam::os::windows2019
        }
        default: { fail('secteam - unsupported operating system, please see readme') }
      }
    }
    'RedHat': {
      case $::os_major_family {
        '8': {
          include secteam::os::rhel8
        }
        default: { fail('secteam - unsupported operating system, please see readme') }
      }
    }
    default: { fail('secteam - unsupported operating system, please see readme') }
  }

}
