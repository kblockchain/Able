// Copyright (c) 2018 The ABLE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ABLE_ACCUMULATORCHECKPOINTS_JSON_H
#define ABLE_ACCUMULATORCHECKPOINTS_JSON_H

#include <string>
std::string GetMainCheckpoints() {
    std::string strMainCheckpoints = "[]";
    return strMainCheckpoints;
}

std::string GetTestCheckpoints() {
    std::string strTestCheckpoints = "[]";
    return strTestCheckpoints;
}

std::string GetRegTestCheckpoints() {
    std::string strRegTestCheckpoints = "[]";
    return strRegTestCheckpoints;
}

#endif //ABLE_ACCUMULATORCHECKPOINTS_JSON_H
