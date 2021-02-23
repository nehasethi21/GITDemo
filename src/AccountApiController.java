package com.ufinity.sls.vle.controller.api;

import com.ufinity.sls.common.ValidationConstants;
import com.ufinity.sls.common.enumeration.audit.AuditAuthAction;
import com.ufinity.sls.common.enumeration.audit.AuditResult;
import com.ufinity.sls.common.service.AuthenticationService;
import com.ufinity.sls.exception.TokenServiceException;
import com.ufinity.sls.model.AccountSetupModel;
import com.ufinity.sls.model.JsonResult;
import com.ufinity.sls.model.user.CurrentUser;
import com.ufinity.sls.repos.repo.model.UserToken;
import com.ufinity.sls.service.MessageSourceService;
import com.ufinity.sls.service.token.TokenService;
import com.ufinity.sls.service.user.CurrentUserProvider;
import com.ufinity.sls.service.user.UserAuthorityService;
import com.ufinity.sls.service.user.UserCredentialService;
import com.ufinity.sls.service.user.student.StudentAccountService;
import com.ufinity.sls.service.user.student.UserProfileService;
import com.ufinity.sls.util.AuditUtils;

import org.apache.commons.validator.routines.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailSendException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpSession;

import static com.ufinity.sls.common.ApiUrlConstants.URL_API_ACCOUNT_OTP_AUTHENTICATE;
import static com.ufinity.sls.common.ApiUrlConstants.URL_API_ACCOUNT_OTP_REQUEST;
import static com.ufinity.sls.common.ApiUrlConstants.URL_API_ACCOUNT_OTP_RESEND;
import static com.ufinity.sls.common.ApiUrlConstants.URL_API_ACCOUNT_SETUP;
import static com.ufinity.sls.common.ApiUrlConstants.URL_API_ACCOUNT_SETUP_INFO;
import static com.ufinity.sls.common.Constants.EVENT_STEP;
import static com.ufinity.sls.common.Constants.SESSION_GET_PROFILE_EMAIL;
import static com.ufinity.sls.common.RolePermissionConstants.ACCOUNT_SETUP;
import static com.ufinity.sls.model.JsonResult.ERROR;
import static com.ufinity.sls.model.JsonResult.NO_ERROR;

/**
 * TODO: To change to @RestController
 */
@Controller
@PreAuthorize("hasAnyAuthority('" + ACCOUNT_SETUP + "')")
public class AccountApiController {
  private static final Logger LOG = LoggerFactory.getLogger(AccountApiController.class);
  private static final String OTP_VERIFICATION_FAILED = "otp.verification.fail";
  private static final String OTP_RESEND_FAILED = "otp.resend.fail";
  private static final String TOKEN_EXPIRED = "token.expired";
  private static final String FAILED = "failed";

  private final AuthenticationService authenticationService;
  private final CurrentUserProvider currentUserProvider;
  private final MessageSourceService messageSourceService;
  private final TokenService profileOtpTokenService;
  private final StudentAccountService studentAccountService;
  private final UserProfileService userProfileService;

  @Autowired
  public AccountApiController(AuthenticationService authenticationService,
                              CurrentUserProvider currentUserProvider,
                              MessageSourceService messageSourceService,
                              TokenService profileOtpTokenService,
                              StudentAccountService studentAccountService,
                              UserProfileService userProfileService) {
    this.authenticationService = authenticationService;
    this.currentUserProvider = currentUserProvider;
    this.messageSourceService = messageSourceService;
    this.profileOtpTokenService = profileOtpTokenService;
    this.studentAccountService = studentAccountService;
    this.userProfileService = userProfileService;
  }

  @Autowired
  private UserAuthorityService userAuthorityService;

  @GetMapping(value = URL_API_ACCOUNT_SETUP_INFO)
  @ResponseBody
  public JsonResult<AccountSetupModel> setupAccount() {
    AccountSetupModel accountSetupModel = studentAccountService.getAccountSetupInfo();
    JsonResult<AccountSetupModel> jsonResult = new JsonResult<>();
    jsonResult.setCode(JsonResult.NO_ERROR);
    jsonResult.setData(accountSetupModel);
    return jsonResult;
  }

  @PostMapping(value = URL_API_ACCOUNT_SETUP)
  @ResponseBody
  public JsonResult accountSetup(@RequestBody Map<String, String> requestData) {
    String eventStep = requestData.get(EVENT_STEP);
    JsonResult<String> result = new JsonResult<>();

    if ("step1".equals(eventStep)) {
      result = studentAccountService.setupPassword(requestData);
    } else if ("step2".equals(eventStep)) {
      result = studentAccountService.setupEmail(requestData);
    } else if ("step3".equals(eventStep)) {
      result = studentAccountService.setupSecurityQuestion(requestData);
      userAuthorityService.updateAuthorities();
    }

    return result;
  }

  @PostMapping(value = URL_API_ACCOUNT_OTP_REQUEST)
  @ResponseBody
  public JsonResult requestOTP(@RequestBody String emailAddress, HttpSession httpSession) {
    JsonResult<Boolean> jsonResult = new JsonResult<>();

    if (EmailValidator.getInstance().isValid(emailAddress)) {
      jsonResult.setCode(JsonResult.NO_ERROR);
      try {
        userProfileService.requestOTP(emailAddress, false);
        httpSession.setAttribute(SESSION_GET_PROFILE_EMAIL, emailAddress);
      } catch (TokenServiceException e) {
        LOG.error("Error requesting OTP: ", e);
        jsonResult.setCode(ERROR);
      } catch (MailSendException e) {
        jsonResult.setCode(ERROR);
      }
    } else {
      jsonResult.setCode(ERROR);
    }
    return jsonResult;
  }

  @PostMapping(value = URL_API_ACCOUNT_OTP_RESEND)
  @ResponseBody
  public JsonResult resendOtp(@RequestBody String emailAddress) {
    long secondsToWait;
    JsonResult<String> jsonResult = new JsonResult<>();

    if (EmailValidator.getInstance().isValid(emailAddress)) {
      CurrentUser currentUser = currentUserProvider.getCurrentUser();

      try {
        userProfileService.requestOTP(emailAddress, true);

        AuditUtils.auditAuthLog(
            LOG,
            currentUser.getIamsId(),
            AuditAuthAction.REQUEST_TWO_FA_TOKEN,
            AuditResult.SUCCESS,
            currentUser.getIamsId() + " " + "OTP token requested successfully."
        );

        return new JsonResult(NO_ERROR);

      } catch (TokenServiceException e) {
        LOG.error("Error resending OTP: ", e);
        String errorMsg = messageSourceService.getMessage(OTP_RESEND_FAILED);

        AuditUtils.auditAuthLog(
            LOG,
            currentUser.getIamsId(),
            AuditAuthAction.REQUEST_TWO_FA_TOKEN,
            AuditResult.FAIL,
            currentUser.getIamsId() + " " + errorMsg
        );

        secondsToWait = e.getWaitingTime();

        jsonResult.setCode(FAILED);
        jsonResult.setError(errorMsg);
        jsonResult.setData(String.valueOf(secondsToWait));
        return jsonResult;
      }
    } else {
      return new JsonResult(ERROR);
    }
  }

  @PostMapping(value = URL_API_ACCOUNT_OTP_AUTHENTICATE)
  @ResponseBody
  public JsonResult authenticate(@RequestParam(value = "otp") String otp, HttpSession httpSession) throws TokenServiceException {
    String emailAddress = (String) httpSession.getAttribute(SESSION_GET_PROFILE_EMAIL);
    CurrentUser currentUser = currentUserProvider.getCurrentUser();

    if (EmailValidator.getInstance().isValid(emailAddress)) {
      JsonResult<String> jsonResult = new JsonResult<>();
      Optional<UserToken> userTokenOptional = profileOtpTokenService.getUserToken(currentUser.getId(), otp);

      if (userTokenOptional.isPresent()) {
        if (profileOtpTokenService.isValidToken(userTokenOptional.get().getToken())) {
          Map<String, String> email = new HashMap<>();
          email.put("email", emailAddress);

          authenticationService.updateUserAuthenticationState();
          studentAccountService.setupEmail(email);

          AuditUtils.auditAuthLog(
              LOG,
              currentUser.getIamsId(),
              AuditAuthAction.TWO_FA_SUCCESS,
              AuditResult.SUCCESS,
              currentUser.getIamsId() + " " + ValidationConstants.AUTHENTICATION_SUCCESSFUL);

          httpSession.removeAttribute(SESSION_GET_PROFILE_EMAIL);

          return new JsonResult(NO_ERROR);

        } else if (LocalDateTime.now().isAfter(userTokenOptional.get().getExpiryTime())) {

          AuditUtils.auditAuthLog(
              LOG,
              currentUser.getIamsId(),
              AuditAuthAction.TWO_FA_SUCCESS,
              AuditResult.SUCCESS,
              currentUser.getIamsId() + "{} Verification code is expired."
          );

          jsonResult.setCode(ERROR);
          jsonResult.setError(TOKEN_EXPIRED);
          return jsonResult;
        }
      }
      AuditUtils.auditAuthLog(
          LOG,
          currentUser.getIamsId(),
          AuditAuthAction.TWO_FA_FAIL,
          AuditResult.FAIL,
          currentUser.getIamsId() + " " + OTP_VERIFICATION_FAILED
      );

      return new JsonResult(ERROR);

    } else {
      AuditUtils.auditAuthLog(
          LOG,
          currentUser.getIamsId(),
          AuditAuthAction.TWO_FA_FAIL,
          AuditResult.FAIL,
          currentUser.getIamsId() + " Invalid email address" );

      return new JsonResult(ERROR);
    }
  }
}
