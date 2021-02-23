package com.ufinity.sls.vle.controller.api;

import com.ufinity.sls.common.annotation.ReadOnlyConnection;
import com.ufinity.sls.common.enumeration.resource.ResourceSharingComponentType;
import com.ufinity.sls.common.enumeration.resource.ResourceType;
import com.ufinity.sls.common.enumeration.resource.lesson.LessonType;
import com.ufinity.sls.model.AccessRightsModel;
import com.ufinity.sls.model.JsonResult;
import com.ufinity.sls.model.LessonModel;
import com.ufinity.sls.model.ResourceUserPermissionModel;
import com.ufinity.sls.repos.repo.model.Lesson;
import com.ufinity.sls.repos.repo.model.User;
import com.ufinity.sls.service.lesson.VleLessonResourceService;
import com.ufinity.sls.service.lesson.impl.LessonMOEWorkflowService;
import com.ufinity.sls.service.lesson.impl.LessonService;
import com.ufinity.sls.service.resource.ResourceSharingService;
import com.ufinity.sls.service.user.CurrentUserProvider;
import com.ufinity.sls.service.user.VleAccessControlService;
import com.ufinity.sls.service.user.VleResourceAccessControlService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.ufinity.sls.common.ApiUrlConstants.URL_MY_LIBRARY_LESSON;
import static com.ufinity.sls.common.ApiUrlConstants.URL_MY_LIBRARY_LESSON_USER_PERMISSIONS;
import static com.ufinity.sls.common.RolePermissionConstants.ROLENAME_ALP_TEMPLATE_ADMIN;
import static com.ufinity.sls.common.RolePermissionConstants.ROLENAME_TEACHER;

/**
 * TODO: To change to @RestController
 */
@Controller
public class PersonalLibraryLessonApiController {

  private final VleResourceAccessControlService vleResourceAccessControlService;
  private final VleLessonResourceService lessonResourceService;
  private final LessonService lessonService;
  private final LessonMOEWorkflowService lessonMOEWorkflowService;
  private final ResourceSharingService resourceSharingService;
  private final DateTimeFormatter dateTimeFormatterUI;
  private final VleAccessControlService vleAccessControlService;
  private final CurrentUserProvider currentUserProvider;

  @Autowired
  public PersonalLibraryLessonApiController(VleResourceAccessControlService vleResourceAccessControlService,
                                            VleLessonResourceService lessonResourceService,
                                            LessonService lessonService,
                                            LessonMOEWorkflowService lessonMOEWorkflowService,
                                            ResourceSharingService resourceSharingService,
                                            DateTimeFormatter dateTimeFormatterUI,
                                            VleAccessControlService vleAccessControlService,
                                            CurrentUserProvider currentUserProvider) {
    this.vleResourceAccessControlService = vleResourceAccessControlService;
    this.lessonResourceService = lessonResourceService;
    this.lessonService = lessonService;
    this.lessonMOEWorkflowService = lessonMOEWorkflowService;
    this.resourceSharingService = resourceSharingService;
    this.dateTimeFormatterUI = dateTimeFormatterUI;
    this.vleAccessControlService = vleAccessControlService;
    this.currentUserProvider = currentUserProvider;
  }

  /**
   * Get lesson
   * @param lessonUuid
   * @return data LessonModel
   */
   @PreAuthorize("hasAnyAuthority('" +  ROLENAME_TEACHER + "','" + ROLENAME_ALP_TEMPLATE_ADMIN + "')")
   @GetMapping(URL_MY_LIBRARY_LESSON)
   @ResponseBody
   @ReadOnlyConnection
   public JsonResult getLesson(@PathVariable String lessonUuid) {
     JsonResult jsonResult = new JsonResult();
     Map<String, Object> modelMap = new HashMap<>();

     Lesson lesson = lessonService.getApprovedCopy(lessonUuid);
     if (
       lesson.getPackageType().isDeprecated() || !lesson.isSearchable() ||
       (!lesson.isSnapshot() && !vleAccessControlService.hasViewPermission(lesson)) ||
       !vleResourceAccessControlService.hasResourceViewRight(lesson)
     ) {
       // 1. Access denied if html5/url lesson, OR
       // 2. Lesson is in trash
       // 3. User has no permission.
       jsonResult.setCode(JsonResult.ERROR);
       jsonResult.setError(AccessRightsModel.ACCESS_DENIED);
       return jsonResult;
     }

     LessonModel lessonModel = lessonResourceService.getModel(lesson);
     lessonModel.setSharedWithMe(resourceSharingService.isResourceShared(lessonUuid, ResourceSharingComponentType.LESSON));
     lessonModel.setDisplayDate(dateTimeFormatterUI);

     lessonService.populateAssignableProperties(lessonModel);
     lessonResourceService.populateAlpStage(modelMap, lessonModel, lesson);
     lessonResourceService.populateParentFolderUuid(lessonModel);
     lessonResourceService.populateParentPath(lessonModel, lesson);
     lessonResourceService.populateResourceTaggingsSummary(lessonModel, lesson);

     jsonResult.setCode(JsonResult.NO_ERROR);
     jsonResult.setData(lessonModel);
     return jsonResult;
   }

  /**
   * Get view lesson permissions
   * @param lessonUuid
   * @return data map
   */
  @PreAuthorize("hasAnyAuthority('" +  ROLENAME_TEACHER + "','" + ROLENAME_ALP_TEMPLATE_ADMIN + "')")
  @GetMapping(URL_MY_LIBRARY_LESSON_USER_PERMISSIONS)
  @ResponseBody
  @ReadOnlyConnection
  public JsonResult<ResourceUserPermissionModel> getViewLessonPermission(@PathVariable UUID lessonUuid) {
    JsonResult<ResourceUserPermissionModel> jsonResult = new JsonResult<>(JsonResult.NO_ERROR);
    ResourceUserPermissionModel permissionModel = new ResourceUserPermissionModel(ResourceType.LESSON, lessonUuid);

    String uuidString = lessonUuid.toString();
    User user = currentUserProvider.getUser();

    Lesson lesson = lessonService.getApprovedCopy(uuidString);
    if (
      lesson.getPackageType().isDeprecated() || !lesson.isSearchable() ||
      (!lesson.isSnapshot() && !vleAccessControlService.hasViewPermission(lesson)) ||
      !vleResourceAccessControlService.hasResourceViewRight(lesson)
    ) {
      // 1. Access denied if html5/url lesson, OR
      // 2. Lesson is in trash
      // 3. User has no permission.
      jsonResult.setCode(JsonResult.ERROR);
      jsonResult.setError(AccessRightsModel.ACCESS_DENIED);
      return jsonResult;
    }

    permissionModel.setHasViewPermission(true);
    permissionModel.setHasEditPermission(vleAccessControlService.hasEditPermission(lesson));
    permissionModel.setHasDeletePermission(vleAccessControlService.hasDeletePermission(lesson));
    permissionModel.setHasDuplicatePermission(true);
    permissionModel.setHasSharePermission(vleAccessControlService.hasSharePermission(lesson));
    permissionModel.setHasSubmitToCgPermission(vleAccessControlService.isOwnerOrHasEditPermission(lesson));
    permissionModel.setHasSubmitToMoePermission(
      lessonMOEWorkflowService.hasSubmitPermission(lesson, user) ||
      lessonMOEWorkflowService.hasApprovePermission(lesson, user)
    );

    jsonResult.setData(permissionModel);
    return jsonResult;
  }
}
