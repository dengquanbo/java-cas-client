/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.cas.client.validation;

import javax.servlet.FilterConfig;

/**
 * Implementation of AbstractTicketValidatorFilter that instanciates a Cas10TicketValidator.
 * <p>Deployers can provide the "casServerPrefix" and the "renew" attributes via the standard context or filter init
 * parameters.
 *
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.1
 */
public class Cas10TicketValidationFilter extends AbstractTicketValidationFilter {
    
    protected final TicketValidator getTicketValidator(final FilterConfig filterConfig) {
        // 获取 casServerUrlPrefix，默认为 null
        final String casServerUrlPrefix = getPropertyFromInitParams(filterConfig, "casServerUrlPrefix", null);
        
        // 创建一个 Cas10TicketValidator ticket检验器
        final Cas10TicketValidator validator = new Cas10TicketValidator(casServerUrlPrefix);
        
        // 获取配置的 renew
        validator.setRenew(parseBoolean(getPropertyFromInitParams(filterConfig, "renew", "false")));
        
        // todo
        // https hostname检验器
        validator.setHostnameVerifier(getHostnameVerifier(filterConfig));
        
        // 获取配置的编码配置
        validator.setEncoding(getPropertyFromInitParams(filterConfig, "encoding", null));
        
        return validator;
    }
}
