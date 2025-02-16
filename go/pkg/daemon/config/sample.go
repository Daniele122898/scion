// Copyright 2018 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

const idSample = "sd"

const sdSample = `
# Address where the SCION Daemon server API is exposed. (default 127.0.0.1:30255)
address = "127.0.0.1:30255"

# Do not force daemon to dial using the local IP address specified above in address. This lets
# the network stack to choose the appropriate address depending on the destination address.
bind_dialer_to_address = false

# Disable segment verification of the daemon. This can be done if it runs in
# the same trust zone as the control service. (default false)
disable_seg_verification = false

# The time after which segments for a destination are refetched. (default 5m)
query_interval = "5m"

# The configuration containing hidden path groups. (default "")
hidden_path_groups =  ""
`
