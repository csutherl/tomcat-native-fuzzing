# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    autoconf \
    libtool \
    libtool-bin \
    pkg-config

# Build APR (required dependency)
RUN git clone --depth 1 https://github.com/apache/apr.git /src/apr
WORKDIR /src/apr
RUN ./buildconf && \
    ./configure --prefix=/usr && \
    make && \
    make install

# Clone tomcat-native
WORKDIR /src
RUN git clone --depth 1 https://github.com/apache/tomcat-native.git

# Copy build script
WORKDIR /src/tomcat-native
COPY build.sh /src/
