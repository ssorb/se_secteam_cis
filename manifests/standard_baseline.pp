# @summary Entry point for Security Team's CIS module.
#
# This module enforces CIS benchmark settings for Windows 2019 and Centos 8 servers. 
# There is a single parameter to optionally set noop mode for the scope of this class.
#
# @example
#   include secteam::standard_baseline
class secteam::standard_baseline {

  $fam = $facts.get('os.family').tolower
  $maj = $facts.get('os.release.major').tolower

  if defined("secteam_cis::${fam}::${maj}") {
    include "secteam_cis::${fam}::${maj}"
  }
  else {
    fail('secteam_cis - unsupported operating system, please see readme')
  }

}
