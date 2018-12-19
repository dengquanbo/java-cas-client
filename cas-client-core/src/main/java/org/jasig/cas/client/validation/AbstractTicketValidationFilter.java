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

import java.io.IOException;

import javax.net.ssl.HostnameVerifier;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;

/**
 * The filter that handles all the work of validating ticket requests.
 * <p>
 * This filter can be configured with the following values:
 * <ul>
 * <li><code>redirectAfterValidation</code> - redirect the CAS client to the
 * same URL without the ticket.</li>
 * <li><code>exceptionOnValidationFailure</code> - throw an exception if the
 * validation fails. Otherwise, continue processing.</li>
 * <li><code>useSession</code> - store any of the useful information in a
 * session attribute.</li>
 * </ul>
 *
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.1
 */
public abstract class AbstractTicketValidationFilter extends AbstractCasFilter {
    
    /** The TicketValidator we will use to validate tickets. */
    private TicketValidator ticketValidator;
    
    /**
     * Specify whether the filter should redirect the user agent after a successful
     * validation to remove the ticket parameter from the query string.
     */
    private boolean redirectAfterValidation = false;
    
    /**
     * Determines whether an exception is thrown when there is a ticket validation
     * failure.
     */
    private boolean exceptionOnValidationFailure = true;
    
    private boolean useSession = true;
    
    /**
     * Template method to return the appropriate validator.
     *
     * @param filterConfig
     *            the FilterConfiguration that may be needed to construct a
     *            validator.
     * @return the ticket validator.
     */
    protected TicketValidator getTicketValidator(final FilterConfig filterConfig) {
        return this.ticketValidator;
    }
    
    /**
     * Gets the configured {@link HostnameVerifier} to use for HTTPS connections if
     * one is configured for this filter.
     *
     * @param filterConfig
     *            Servlet filter configuration.
     * @return Instance of specified host name verifier or null if none specified.
     */
    protected HostnameVerifier getHostnameVerifier(final FilterConfig filterConfig) {
        final String className = getPropertyFromInitParams(filterConfig, "hostnameVerifier", null);
        log.trace("Using hostnameVerifier parameter: " + className);
        final String config = getPropertyFromInitParams(filterConfig, "hostnameVerifierConfig", null);
        log.trace("Using hostnameVerifierConfig parameter: " + config);
        if (className != null) {
            if (config != null) {
                return ReflectUtils.newInstance(className, config);
            } else {
                return ReflectUtils.newInstance(className);
            }
        }
        return null;
    }
    
    protected void initInternal(final FilterConfig filterConfig) throws ServletException {
        setExceptionOnValidationFailure(
            parseBoolean(getPropertyFromInitParams(filterConfig, "exceptionOnValidationFailure", "true")));
        log.trace("Setting exceptionOnValidationFailure parameter: " + this.exceptionOnValidationFailure);
        setRedirectAfterValidation(
            parseBoolean(getPropertyFromInitParams(filterConfig, "redirectAfterValidation", "true")));
        log.trace("Setting redirectAfterValidation parameter: " + this.redirectAfterValidation);
        setUseSession(parseBoolean(getPropertyFromInitParams(filterConfig, "useSession", "true")));
        log.trace("Setting useSession parameter: " + this.useSession);
        // 子类实现 getTicketValidator() 方法，从而实现不同的 TicketValidator
        setTicketValidator(getTicketValidator(filterConfig));
        super.initInternal(filterConfig);
    }
    
    public void init() {
        super.init();
        CommonUtils.assertNotNull(this.ticketValidator, "ticketValidator cannot be null.");
    }
    
    /**
     * Pre-process the request before the normal filter process starts. This could
     * be useful for pre-empting code.
     *
     * @param servletRequest
     *            The servlet request.
     * @param servletResponse
     *            The servlet response.
     * @param filterChain
     *            the filter chain.
     * @return true if processing should continue, false otherwise.
     * @throws IOException
     *             if there is an I/O problem
     * @throws ServletException
     *             if there is a servlet problem.
     */
    protected boolean preFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                                final FilterChain filterChain) throws IOException, ServletException {
        return true;
    }
    
    /**
     * Template method that gets executed if ticket validation succeeds. Override if
     * you want additional behavior to occur if ticket validation succeeds. This
     * method is called after all ValidationFilter processing required for a
     * successful authentication occurs.
     *
     * @param request
     *            the HttpServletRequest.
     * @param response
     *            the HttpServletResponse.
     * @param assertion
     *            the successful Assertion from the server.
     */
    protected void onSuccessfulValidation(final HttpServletRequest request, final HttpServletResponse response,
                                          final Assertion assertion) {
        // nothing to do here.
    }
    
    /**
     * Template method that gets executed if validation fails. This method is called
     * right after the exception is caught from the ticket validator but before any
     * of the processing of the exception occurs.
     *
     * @param request
     *            the HttpServletRequest.
     * @param response
     *            the HttpServletResponse.
     */
    protected void onFailedValidation(final HttpServletRequest request, final HttpServletResponse response) {
        // nothing to do here.
    }
    
    public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                               final FilterChain filterChain) throws IOException, ServletException {
        // 用于过滤前的调用，子类实现
        // Cas10TicketValidationFilter 未实现
        // Cas20ProxyReceivingTicketValidationFilter 有实现
        if (!preFilter(servletRequest, servletResponse, filterChain)) {
            return;
        }
        
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        
        // 从请求中拿到 ticket
        // 如：http://client.dqb.cn:8084?ticket=ST-220-kRILeoBORl9OZJMehwoy-cas01.example.org
        final String ticket = CommonUtils.safeGetParameter(request, getArtifactParameterName());
        
        // 如果请求中携带有 ticket，需判断 ticket 是否有效
        if (CommonUtils.isNotBlank(ticket)) {
            if (log.isDebugEnabled()) {
                log.debug("Attempting to validate ticket: " + ticket);
            }
            
            try {
                // constructServiceUrl 方法用于构建请求，如编码
                final Assertion assertion = this.ticketValidator.validate(ticket,
                    constructServiceUrl(request, response));
                
                if (log.isDebugEnabled()) {
                    log.debug("Successfully authenticated user: " + assertion.getPrincipal().getName());
                }
                
                // ticket 校验成功，放入 request 作用域中，key = _const_cas_assertion_
                request.setAttribute(CONST_CAS_ASSERTION, assertion);
                
                // ticket 校验成功，放入 session 作用域中，key = _const_cas_assertion_
                if (this.useSession) {
                    request.getSession().setAttribute(CONST_CAS_ASSERTION, assertion);
                }
                
                // 模版方法，ticket 校验成功后调用，子类实现
                onSuccessfulValidation(request, response, assertion);
                
                // 检验成功后，是否直接跳转，否则进入下一个 filter
                if (this.redirectAfterValidation) {
                    log.debug("Redirecting after successful ticket validation.");
                    response.sendRedirect(constructServiceUrl(request, response));
                    return;
                }
            } catch (final TicketValidationException e) {
                // ticket 检验失败会进入这个逻辑
                // 设置状态码为 403
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                // 打印日志
                log.warn(e, e);
                
                // 模版方法，用于 ticket 检验失败后的处理，子类实现
                onFailedValidation(request, response);
                
                // ticket 检验失败，需抛出 ServletException 异常
                // 此时前端页面会显示异常：HTTP Status 500 -
                // org.jasig.cas.client.validation.TicketValidationException: CAS
                // Server could not validate ticket.
                // 为了不使异常抛到前端，在过滤其中配置此参数为 false，
                /**
                 * <pre>
                 *     <init-param>
                 *             <param-name>exceptionOnValidationFailure</param-name>
                 *             <param-value>false</param-value>
                 *         </init-param>
                 * </pre>
                 */
                // 此时显示：访问 170.240.110.223 的请求遭到拒绝 您未获授权，无法查看此网页。
                if (this.exceptionOnValidationFailure) {
                    throw new ServletException(e);
                }
                
                return;
            }
        }
        
        // 进入下一个 filter
        filterChain.doFilter(request, response);
        
    }
    
    public final void setTicketValidator(final TicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }
    
    public final void setRedirectAfterValidation(final boolean redirectAfterValidation) {
        this.redirectAfterValidation = redirectAfterValidation;
    }
    
    public final void setExceptionOnValidationFailure(final boolean exceptionOnValidationFailure) {
        this.exceptionOnValidationFailure = exceptionOnValidationFailure;
    }
    
    public final void setUseSession(final boolean useSession) {
        this.useSession = useSession;
    }
    
}
