/*
 * Copyright (c) 2016 VMware, Inc. All Rights Reserved.
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.vmware.burp.extension.domain;

import burp.IParameter;

public enum ParameterType {
   PARAM_BODY(IParameter.PARAM_BODY),
   PARAM_COOKIE(IParameter.PARAM_COOKIE),
   PARAM_JSON(IParameter.PARAM_JSON),
   PARAM_MULTIPART_ATTR(IParameter.PARAM_MULTIPART_ATTR),
   PARAM_URL(IParameter.PARAM_URL),
   PARAM_XML(IParameter.PARAM_XML),
   PARAM_XML_ATTR(IParameter.PARAM_XML_ATTR);

   private byte parameterType;

   private ParameterType(byte parameterType) {
      this.parameterType = parameterType;
   }

   private byte getValue() {
       return parameterType;
   }

   public static ParameterType getEnum(byte type) {
       for (ParameterType parameterType : values()) {
          if (parameterType.getValue() == type) {
             return parameterType;
          }
       }
       throw new IllegalArgumentException();
   }
}
