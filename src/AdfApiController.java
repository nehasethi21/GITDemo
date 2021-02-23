package com.ufinity.sls.vle.controller.api;

import com.ufinity.sls.common.enumeration.PendingActionType;
import com.ufinity.sls.common.enumeration.app.AppType;
import com.ufinity.sls.exception.DisabledAppException;
import com.ufinity.sls.exception.EntityNotFoundException;
import com.ufinity.sls.model.AppContextModel;
import com.ufinity.sls.model.JsonResult;
import com.ufinity.sls.model.user.CurrentUser;
import com.ufinity.sls.repos.repo.dao.AppAvailabilityDao;
import com.ufinity.sls.repos.repo.dao.AppDao;
import com.ufinity.sls.repos.repo.dao.AppEndpointDao;
import com.ufinity.sls.repos.repo.dao.AppInstallationDao;
import com.ufinity.sls.repos.repo.dao.PendingActionDao;
import com.ufinity.sls.repos.repo.model.App;
import com.ufinity.sls.repos.repo.model.AppAssignment;
import com.ufinity.sls.repos.repo.model.AppContext;
import com.ufinity.sls.repos.repo.model.AppContextEvent;
import com.ufinity.sls.repos.repo.model.AppEndpoint;
import com.ufinity.sls.repos.repo.model.Assignment;
import com.ufinity.sls.repos.repo.model.PendingAction;
import com.ufinity.sls.repos.repo.model.StudentGroup;
import com.ufinity.sls.repos.repo.model.StudentGroupCollection;
import com.ufinity.sls.service.app.AppService;
import com.ufinity.sls.service.app.AppValidationService;
import com.ufinity.sls.service.assignment.AssignmentAccessRightsService;
import com.ufinity.sls.service.assignment.AssignmentService;
import com.ufinity.sls.service.studentgroup.GroupMembershipService;
import com.ufinity.sls.service.studentgroup.StudentGroupCollectionService;
import com.ufinity.sls.service.user.CurrentUserProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static com.ufinity.sls.common.ApiUrlConstants.URL_GENERATE_APP_CONTEXT;

@RestController
public class AdfApiController {
  private static final Logger LOG = LoggerFactory.getLogger(AdfApiController.class);

  private static final String GROUP_ACCESS_DENIED_MESSAGE = " doesn't has permission to access subject group ";

  private final AppDao appDao;
  private final AppService appService;
  private final AppValidationService appValidationService;
  private final CurrentUserProvider currentUserProvider;
  private final StudentGroupCollectionService studentGroupCollectionService;
  private final GroupMembershipService groupMembershipService;
  private final AppEndpointDao appEndpointDao;
  private final AssignmentService assignmentService;
  private final AssignmentAccessRightsService assignmentAccessRightsService;
  private final AppAvailabilityDao appAvailabilityDao;
  private final AppInstallationDao appInstallationDao;
  private final PendingActionDao pendingActionDao;

  @Autowired
  public AdfApiController(AppDao appDao,
                          AppService appService,
                          AppValidationService appValidationService,
                          CurrentUserProvider currentUserProvider,
                          StudentGroupCollectionService studentGroupCollectionService,
                          GroupMembershipService groupMembershipService,
                          AppEndpointDao appEndpointDao,
                          AssignmentService assignmentService,
                          AssignmentAccessRightsService assignmentAccessRightsService,
                          AppAvailabilityDao appAvailabilityDao,
                          AppInstallationDao appInstallationDao,
                          PendingActionDao pendingActionDao) {
    this.appDao = appDao;
    this.appService = appService;
    this.appValidationService = appValidationService;
    this.currentUserProvider = currentUserProvider;
    this.studentGroupCollectionService = studentGroupCollectionService;
    this.groupMembershipService = groupMembershipService;
    this.appEndpointDao = appEndpointDao;
    this.assignmentService = assignmentService;
    this.assignmentAccessRightsService = assignmentAccessRightsService;
    this.appAvailabilityDao = appAvailabilityDao;
    this.appInstallationDao = appInstallationDao;
    this.pendingActionDao = pendingActionDao;
  }


  @GetMapping(URL_GENERATE_APP_CONTEXT)
  @ResponseBody
  public JsonResult<AppContextModel> generateAppContext(@RequestParam(required = false) String appUuid,
                                                        @RequestParam String type,
                                                        @RequestParam(required = false) String collectionUuid,
                                                        @RequestParam(required = false) String collectionId,
                                                        @RequestParam(required = false) String assignmentUuid,
                                                        @RequestParam(required = false) String endpointUuid) {
    JsonResult<AppContextModel> jsonResult = new JsonResult<>();

    try {
      if (collectionUuid == null && collectionId != null) {
        StudentGroupCollection
            studentGroupCollection =
            studentGroupCollectionService.findById(Long.parseLong(collectionId));
        collectionUuid = studentGroupCollection.getUuid().toString();
      }

      if (collectionUuid == null) {
        jsonResult.setCode(JsonResult.ERROR);
        return jsonResult;
      }

      StudentGroup studentGroup = groupMembershipService.getStudentGroupOfCollection(UUID.fromString(collectionUuid));
      AppContextModel appContextModel = null;

      switch (type) {
        case AppContextEvent.LAUNCH_APP:
        case AppContextEvent.LAUNCH_URL:
          App app = appDao.findByUuid(UUID.fromString(appUuid));
          validateLaunchApp(studentGroup, app, collectionUuid);

          if (app.getType() == AppType.GRAPHQL) {
            appContextModel = getGraphQLAppContext(studentGroup, endpointUuid, app);
          } else if (app.getType() == AppType.LTI13) {
            appContextModel = getLTIAppContext(app, collectionUuid, appUuid);
          }
          break;
        case AppContextEvent.LAUNCH_ASSIGNMENT:
        case AppContextEvent.LAUNCH_TASK:
          Assignment assignment = assignmentService.findByUuid(assignmentUuid);
          if (assignment instanceof AppAssignment) {
            // separate handling of view page for APP assignments
            AppAssignment appAssignment = (AppAssignment) assignment;
            validateLaunchAssignment(appAssignment, studentGroup);
            appContextModel = getAppAssignmentContext(appAssignment, type);
          }
          break;
        default:
          jsonResult.setCode(JsonResult.ERROR);
          return jsonResult;
      }
      if (appContextModel == null) {
        jsonResult.setCode(JsonResult.ERROR);
        return jsonResult;
      }
      jsonResult.setData(appContextModel);
      jsonResult.setCode(JsonResult.NO_ERROR);
    } catch (EntityNotFoundException | AccessDeniedException e) {
      LOG.warn("Unable to generate app context", e);
      jsonResult.setCode(JsonResult.ERROR);
    } catch (Exception e) {
      jsonResult.setCode(JsonResult.ERROR);
      LOG.warn("Exception occurred while generating app context.", e);
    }
    return jsonResult;
  }

  // TODO: move following private method to relevant service, we app AppService, AppValidationService .etc

  private void validateLaunchApp(StudentGroup studentGroup, App app, String groupUuid) {
    CurrentUser currentUser = currentUserProvider.getCurrentUser();

    if (studentGroup == null) {
      LOG.warn("[Launch App] no student group for collection {}", groupUuid);
      throw new EntityNotFoundException(
          currentUser.getUuid() + GROUP_ACCESS_DENIED_MESSAGE + groupUuid);
    }

    if (app == null) {
      LOG.warn("[Launch App] no app for collection {}", groupUuid);
      throw new EntityNotFoundException(
          currentUser.getUuid() + GROUP_ACCESS_DENIED_MESSAGE + groupUuid);

    } else if (!app.isEnabled()) {
      LOG.warn("[Launch App] App is disabled for collection {}", groupUuid);
      throw new DisabledAppException("User " + currentUser.getIamsId() + "cannot create app context.", app);
    }

    if (!appValidationService
        .hasLaunchInstalledAppPermission(app.getId(), studentGroup.getStudentGroupCollectionId())) {
      LOG.warn("[Launch App] user {} is trying to access collection {}", currentUserProvider.getCurrentUser().getId(),
          groupUuid);
      throw new AccessDeniedException(
          currentUser.getUuid() + GROUP_ACCESS_DENIED_MESSAGE + groupUuid);
    }
  }

  private void validateLaunchAssignment(AppAssignment appAssignment, StudentGroup studentGroup) {
    App app = appAssignment.getApp();
    CurrentUser currentUser = currentUserProvider.getCurrentUser();
    String
        errorMessage =
        "User " + currentUser.getIamsId() + " is not allowed to view the assignment " + appAssignment.getUuid();

    validateAppAvailBeforeLaunch(app, currentUser, errorMessage);
    validateAppInstallationBeforeLaunch(app, studentGroup, errorMessage);
    validateAccessRightsBeforeLaunch(appAssignment, app, errorMessage);
  }

  private void validateAppAvailBeforeLaunch(App app, CurrentUser currentUser, String errorMessage) {
    // Checking for the case app is not available
    boolean isAppAvailable = true;
    long currentUserId = currentUser.getId();
    if (currentUserProvider.isStudent()) {
      isAppAvailable = appAvailabilityDao.isAvailableToStudent(app.getId(), currentUserId) == 1;
    } else if (currentUserProvider.isTeacher()) {
      isAppAvailable = appAvailabilityDao.isAvailableToTeacher(app.getId(), currentUserId) == 1;
    }
    if (!isAppAvailable) {
      throw new AccessDeniedException(errorMessage);
    }
  }

  private void validateAppInstallationBeforeLaunch(App app, StudentGroup studentGroup, String errorMessage) {
    // Checking for the case app is uninstalled
    if (!appInstallationDao
        .existsByApp_IdAndStudentGroupCollectionId(app.getId(), studentGroup.getStudentGroupCollectionId())) {
      throw new DisabledAppException(errorMessage, app);
    }
  }

  private void validateAccessRightsBeforeLaunch(AppAssignment appAssignment, App app, String errorMessage) {
    CurrentUser currentUser = currentUserProvider.getCurrentUser();

    if (!assignmentAccessRightsService.canAccessAssignment(appAssignment, currentUser.getId())) {
      if (app.isEnabled()) {
        throw new AccessDeniedException(errorMessage);
      } else {
        throw new DisabledAppException(errorMessage, app);
      }
    }
  }

  private AppContextModel getAppAssignmentContext(AppAssignment appAssignment, String type) {
    App app = appAssignment.getApp();

    if (app == null) {
      throw new EntityNotFoundException("App not found in assignment {}", appAssignment.getUuid());
    }

    CurrentUser currentUser = currentUserProvider.getCurrentUser();
    long currentUserId = currentUser.getId();
    AppContextEvent appContextEvent;

    if (type.equals(AppContextEvent.LAUNCH_TASK)) {
      PendingAction
          pendingAction =
          pendingActionDao.findByStudentIdAndAssignmentUuidAndType(currentUserId, appAssignment.getUuid(),
              PendingActionType.ASSIGNMENT);

      if (pendingAction == null) {
        throw new EntityNotFoundException(
            "Task does not exist for User " + currentUserId + " in Assignment " + appAssignment.getUuid());
      }
      appContextEvent =
          new AppContextEvent(AppContextEvent.LAUNCH_TASK, pendingAction.getUuid().toString(), null);
    } else {
      appContextEvent =
          new AppContextEvent(AppContextEvent.LAUNCH_ASSIGNMENT, appAssignment.getUuid(), null);
    }

    AppContext appContext =
        appService.createContext(app, appContextEvent);

    String contextId = appContext.getUuid().toString();
    String launchUrl = app.getDefaultLaunchUrl()
        + (app.getDefaultLaunchUrl().contains("?") ? "&contextId=" : "?contextId=")
        + contextId;

    AppContextModel appContextModel = new AppContextModel();
    appContextModel.setContextId(contextId);
    appContextModel.setLaunchUrl(launchUrl);

    return appContextModel;
  }

  private AppContextModel getGraphQLAppContext(StudentGroup studentGroup, String endpointUuid, App app) {
    StudentGroupCollection
        collection =
        studentGroupCollectionService.findById(studentGroup.getStudentGroupCollectionId());

    AppEndpoint appEndpoint;
    if (endpointUuid == null) {
      appEndpoint = null;
    } else {
      appEndpoint = appEndpointDao.findByUuid(UUID.fromString(endpointUuid));
    }

    String launchKey = appEndpoint == null ? null : appEndpoint.getLaunchKey();

    AppContextEvent
        appContextEvent =
        new AppContextEvent(AppContextEvent.LAUNCH_APP, collection.getUuid().toString(), launchKey);
    AppContext appContext = appService.createContext(app, appContextEvent);

    String appContextUuidString = appContext.getUuid().toString();
    URI launchUri =
        UriComponentsBuilder.fromUriString(app.getDefaultLaunchUrl())
            .queryParam("contextId", appContextUuidString).build().toUri();
    String uriString = launchUri.toString();

    if (!uriString.contains("https://")) {
      uriString = "https://" + uriString;
    }

    AppContextModel appContextModel = new AppContextModel();
    appContextModel.setContextId(appContextUuidString);
    appContextModel.setLaunchUrl(uriString);

    return appContextModel;
  }

  private AppContextModel getLTIAppContext(App app, String groupUuid, String appUuid) {
    String toolId = app.getUuid().toString();
    String
        targetLinkUri =
        Base64.getUrlEncoder().encodeToString(app.getDefaultLaunchUrl().getBytes(StandardCharsets.UTF_8));
    String resourceLinkId = groupUuid + "_" + appUuid;
    URI launchUri = UriComponentsBuilder.fromUriString("/lti/launch/resource-link")
        .queryParam("toolId", toolId)
        .queryParam("contextId", groupUuid)
        .queryParam("targetLinkUri", targetLinkUri)
        .queryParam("resourceLinkId", resourceLinkId)
        .build().toUri();
    String uriString = launchUri.toString();
    return new AppContextModel(null, toolId, groupUuid, targetLinkUri, resourceLinkId, uriString);
  }
}
