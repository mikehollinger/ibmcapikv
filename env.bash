# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: env.bash $
#
# IBM Data Engine for NoSQL - Power Systems Edition User Library Project
#
# Contributors Listed Below - COPYRIGHT 2014,2015
# [+] International Business Machines Corp.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# IBM_PROLOG_END_TAG



#allow a user to specify a custom RC file if needed
#e.g. disable the advanced toolchain with "export USE_ADVANCED_TOOLCHAIN=no"
if [ -e ./customrc ]; then
    echo "INFO: Running customrc"
    set -x
    . ./customrc
    set +x
fi

##  setup git hooks for this session
##   adds prologs and Change-IDs for gerrit
export SURELOCKROOT=`pwd`
TOOLSDIR=${SURELOCKROOT}/src/build/tools
if [ -e $TOOLSDIR/setupgithooks.sh ]; then
    echo "Setting up gerrit hooks."
    $TOOLSDIR/setupgithooks.sh
fi



#configure advanced toolchain for linux
AT70PATH=/opt/at7.0
AT71PATH=/opt/at7.1
AT80PATH=/opt/at8.0




if [ -d $AT70PATH ]; then
    export ADV_TOOLCHAIN_PATH=$AT70PATH
elif [ -d $AT71PATH ]; then
    export ADV_TOOLCHAIN_PATH=$AT71PATH
elif [ -d $AT80PATH ]; then
    export ADV_TOOLCHAIN_PATH=$AT80PATH
else
    echo "WARNING: no toolchain was found. Will fall back to system defaults. YMMV."
fi

export PATH=${PATH}:`pwd`/src/build/tools



#enable advanced toolchain, if no one has an opinion
if [ -z "$USE_ADVANCED_TOOLCHAIN" ]; then
    #enabling advanced toolchain by default. If you don't want this, set USED_ADVANCED_TOOLCHAIN in your environment
    export USE_ADVANCED_TOOLCHAIN=yes
fi
if [ "$USE_ADVANCED_TOOLCHAIN" = "yes" ]; then
    echo "INFO: Enabling Advanced Toolchain: $ADV_TOOLCHAIN_PATH"
    export PATH=${ADV_TOOLCHAIN_PATH}/bin:${ADV_TOOLCHAIN_PATH}/sbin:${PATH}
else
    echo "INFO: Advanced Toolchain Disabled."
fi


#fix up sandboxes in ODE, if we need to
if [ -n "${SANDBOXROOT}" ]; then
    if [ -n "${SANDBOXNAME}" ]; then
        export SANDBOXBASE="${SANDBOXROOT}/${SANDBOXNAME}"
    fi
fi

#set the default ulimit -c for a developer
ulimit -c unlimited
