package io.transwarp.guardian.client.v2;

import io.transwarp.guardian.client.impl.rest.v2.GuardianClientV2RestImpl;
import io.transwarp.guardian.common.conf.GuardianConfiguration;
import io.transwarp.guardian.common.conf.GuardianConstants;
import io.transwarp.guardian.common.conf.GuardianVars;
import io.transwarp.guardian.common.exception.ErrorCodes;
import io.transwarp.guardian.common.exception.GuardianClientException;
import io.transwarp.guardian.common.exception.GuardianException;
import io.transwarp.guardian.common.model.PrincipalType;
import io.transwarp.guardian.common.model.PrincipalVo;
import io.transwarp.guardian.common.model.v2.*;
import org.apache.commons.lang.RandomStringUtils;
import org.junit.*;

import java.util.Arrays;
import java.util.List;

import static io.transwarp.guardian.common.model.PrincipalType.USER;
import static io.transwarp.guardian.common.constants.DataSourceConstants.V2Constants.*;

public class RestClientPermTest {
  private static final String PREFIX = RandomStringUtils.randomAlphabetic(5) + "RestClientPermTest";
  
  private GuardianClientV2 guardianClient;
  
  private ResourceVo hdfsGlobal = ResourceVo.global("HDFS", PREFIX + "hdfs1");
  private ResourceVo hdfsRoot = hdfsGlobal.service().addNode(DIR, "/").build();
  private ResourceVo hdfsTmp = hdfsRoot.asParent().addNode(DIR, "tmp").build();
  private ResourceVo hdfsFile = hdfsRoot.asParent().addNode(FILE, "aaa").build();
  
  private ResourceVo yarnGlobal = ResourceVo.global("YARN", PREFIX + "yarn1");
  private ResourceVo yarnRoot = yarnGlobal.service().addNode(QUEUE, "root").build();
  private ResourceVo yarnDefault = yarnRoot.asParent().addNode(QUEUE, "default").build();
  private ResourceVo yarnIdc = yarnRoot.asParent().addNode(QUEUE, "idc").build();
  private ResourceVo yarnDep = yarnIdc.asParent().addNode(QUEUE, "dep").build();
  
  private static final PermActionVo READ = new PermActionVo("READ");
  private static final PermActionVo WRITE = new PermActionVo("WRITE");
  private static final PermActionVo EXEC = new PermActionVo("EXEC");
  
  private static final PermActionVo SUBMIT = new PermActionVo("SUBMIT");
  private static final PermActionVo DELETE = new PermActionVo("DELETE");
  
  @Before
  public void setup() throws GuardianClientException {
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    guardianClient = new GuardianClientV2RestImpl(configuration);
  }
  
  @After
  public void teardown() {

  }
  
  @Test
  public void testPermOps() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    RoleVo roleVo = new RoleVo(PREFIX + "r");
    guardianClient.addRole(roleVo);
    GroupVo groupVo = new GroupVo(PREFIX + "g");
    guardianClient.addGroup(groupVo);
    guardianClient.assignRole(new UserRoleVo(userVo.getUsername(), roleVo.getRoleName()));
    guardianClient.assignRole(new GroupRoleVo(groupVo.getGroupName(), roleVo.getRoleName()));
    guardianClient.assignGroup(PrincGroupVo.userGroup(userVo.getUsername(), groupVo));
    
    PermVo hdfsGlobalAdmin = new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsTmpRead = new PermVo(hdfsTmp, READ);
    PermVo hdfsFileWrite = new PermVo(hdfsFile, WRITE);
    PermVo yarnGlobalAdmin = new PermVo(yarnGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo yarnDefaultSubmit = new PermVo(yarnDefault, SUBMIT);
    PermVo yarnDepDelete = new PermVo(yarnDep, DELETE);
    
    guardianClient.addPerm(hdfsGlobalAdmin);
    guardianClient.addPerm(hdfsTmpRead);
    guardianClient.addPerm(hdfsFileWrite);
    guardianClient.addPerm(yarnGlobalAdmin);
    guardianClient.addPerm(yarnDefaultSubmit);
    guardianClient.addPerm(yarnDepDelete);
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalAdmin));
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalAdmin, true));
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsFileWrite));
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsFileWrite, true));
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsFileWrite));
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), yarnDepDelete, true));
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), yarnDepDelete));
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnDepDelete));
    
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), hdfsGlobalAdmin, true));
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), hdfsFileWrite, true));
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), yarnDepDelete, false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsTmpRead, false));
    
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), true));
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
    
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), true));
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsTmpRead, yarnGlobalAdmin, yarnDefaultSubmit), false));
    
    List<NodeVo> hdfsRootChildren = guardianClient.getChildNodes(hdfsRoot);
    Assert.assertEquals(2, hdfsRootChildren.size());
    Assert.assertTrue(hdfsRootChildren.contains(new NodeVo(DIR, "tmp")));
    Assert.assertTrue(hdfsRootChildren.contains(new NodeVo(FILE, "aaa")));
    
    List<NodeVo> yarnRootChildren = guardianClient.getChildNodes(yarnRoot);
    Assert.assertEquals(2, yarnRootChildren.size());
    Assert.assertTrue(yarnRootChildren.contains(new NodeVo(QUEUE, "idc")));
    Assert.assertTrue(yarnRootChildren.contains(new NodeVo(QUEUE, "default")));
    
    List<ResourceVo> yarnRootDescendants = guardianClient.getDescendantResources(yarnRoot);
    Assert.assertEquals(2, yarnRootDescendants.size());
    Assert.assertTrue(yarnRootDescendants.contains(yarnDefault));
    Assert.assertTrue(yarnRootDescendants.contains(yarnDep));
    
    List<ResourceVo> yarnDescendants = guardianClient.getDescendantResources(yarnGlobal.service().build());
    Assert.assertEquals(3, yarnDescendants.size());
    Assert.assertTrue(yarnDescendants.contains(yarnGlobal));
    Assert.assertTrue(yarnDescendants.contains(yarnDefault));
    Assert.assertTrue(yarnDescendants.contains(yarnDep));
    
    List<PermActionVo> hdfsRootPermActions = guardianClient.getResourcePermActions(hdfsRoot);
    Assert.assertTrue(hdfsRootPermActions.isEmpty());
    List<PermActionVo> hdfsTmpPermActions = guardianClient.getResourcePermActions(hdfsTmp);
    Assert.assertEquals(1, hdfsTmpPermActions.size());
    Assert.assertTrue(hdfsTmpPermActions.contains(READ));
    
    List<PrincPermVo> hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(USER, hdfsGlobalAdmin, false);
    Assert.assertEquals(1, hdfsGlobalAdminPrincs.size());
    Assert.assertTrue(hdfsGlobalAdminPrincs.contains(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin, false)));
    List<PrincPermVo> yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(USER, yarnDepDelete, true);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.userPerm(userVo.getUsername(), yarnDepDelete, true)));
    
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, hdfsGlobalAdmin, false);
    Assert.assertEquals(1, hdfsGlobalAdminPrincs.size());
    Assert.assertTrue(hdfsGlobalAdminPrincs.contains(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalAdmin, false)));
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, yarnDepDelete, true);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.groupPerm(groupVo.getGroupName(), yarnDepDelete, false)));
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, hdfsGlobalAdmin, true);
    Assert.assertEquals(1, hdfsGlobalAdminPrincs.size());
    Assert.assertTrue(hdfsGlobalAdminPrincs.contains(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalAdmin, true)));
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, yarnDepDelete, false);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnDepDelete, false)));
    
    List<ResourceVo> userAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.user(userVo.getUsername()), PREFIX + "hdfs1", true);
    Assert.assertEquals(2, userAuthorizedResources.size());
    Assert.assertTrue(userAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsGlobal.getDataSource()).build()));
    Assert.assertTrue(userAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsFile.getDataSource()).build()));
    
    List<ResourceVo> groupAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.group(groupVo.getGroupName()), PREFIX + "hdfs1", true);
    Assert.assertEquals(2, groupAuthorizedResources.size());
    Assert.assertTrue(groupAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsGlobal.getDataSource()).build()));
    Assert.assertTrue(groupAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsFile.getDataSource()).build()));
    
    List<ResourceVo> roleAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.role(roleVo.getRoleName()), PREFIX + "yarn1", false);
    Assert.assertEquals(1, roleAuthorizedResources.size());
    Assert.assertTrue(roleAuthorizedResources.contains(new ResourceVo.Builder().dataSource(yarnDep.getDataSource()).build()));
    
    List<PermVo> userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsGlobal, true);
    Assert.assertEquals(1, userPerms.size());
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsFile, false);
    Assert.assertEquals(1, userPerms.size());
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsFile, WRITE)));
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsTmp, true);
    Assert.assertEquals(0, userPerms.size());
    
    List<PermVo> groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsGlobal, true);
    Assert.assertEquals(1, groupPerms.size());
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsFile, true);
    Assert.assertEquals(1, groupPerms.size());
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsFile, WRITE)));
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsTmp, true);
    Assert.assertEquals(0, groupPerms.size());
    
    List<PermVo> rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsGlobal, true, true);
    Assert.assertEquals(1, rolePerms.size());
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsFile, true, true);
    Assert.assertEquals(1, rolePerms.size());
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsFile, WRITE)));
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsTmp, true, true);
    Assert.assertEquals(0, rolePerms.size());
    
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), false);
    Assert.assertEquals(3, userPerms.size());
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsFile, WRITE)));
    Assert.assertTrue(userPerms.contains(new PermVo(yarnDep, DELETE)));
    
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), true);
    Assert.assertEquals(3, groupPerms.size());
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsFile, WRITE)));
    Assert.assertTrue(groupPerms.contains(new PermVo(yarnDep, DELETE)));
    
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), false);
    Assert.assertEquals(3, rolePerms.size());
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsFile, WRITE)));
    Assert.assertTrue(rolePerms.contains(new PermVo(yarnDep, DELETE)));
    
    
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalAdmin, false));
  
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), hdfsGlobalAdmin, false));
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), hdfsFileWrite, true));
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), yarnDepDelete, false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsTmpRead, false));
    
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), true));
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
  
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), true));
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsTmpRead, yarnGlobalAdmin, yarnDefaultSubmit), false));
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(USER, hdfsGlobalAdmin, true);
    Assert.assertEquals(1, hdfsGlobalAdminPrincs.size());
    Assert.assertTrue(hdfsGlobalAdminPrincs.contains(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin, false)));
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(USER, yarnDepDelete, true);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.userPerm(userVo.getUsername(), yarnDepDelete, true)));
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, hdfsGlobalAdmin, true);
    Assert.assertEquals(1, hdfsGlobalAdminPrincs.size());
    Assert.assertTrue(hdfsGlobalAdminPrincs.contains(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalAdmin, false)));
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, yarnDepDelete, true);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.groupPerm(groupVo.getGroupName(), yarnDepDelete, false)));
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, hdfsGlobalAdmin, true);
    Assert.assertEquals(1, hdfsGlobalAdminPrincs.size());
    Assert.assertTrue(hdfsGlobalAdminPrincs.contains(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalAdmin, false)));
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, yarnDepDelete, false);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnDepDelete, false)));
  
    userAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.user(userVo.getUsername()), PREFIX + "hdfs1", true);
    Assert.assertEquals(2, userAuthorizedResources.size());
    Assert.assertTrue(userAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsGlobal.getDataSource()).build()));
    Assert.assertTrue(userAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsFile.getDataSource()).build()));
  
    groupAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.group(groupVo.getGroupName()), PREFIX + "hdfs1", true);
    Assert.assertEquals(2, groupAuthorizedResources.size());
    Assert.assertTrue(groupAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsGlobal.getDataSource()).build()));
    Assert.assertTrue(groupAuthorizedResources.contains(new ResourceVo.Builder().dataSource(hdfsFile.getDataSource()).build()));
  
    roleAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.role(roleVo.getRoleName()), PREFIX + "yarn1", false);
    Assert.assertEquals(1, roleAuthorizedResources.size());
    Assert.assertTrue(roleAuthorizedResources.contains(new ResourceVo.Builder().dataSource(yarnDep.getDataSource()).build()));
  
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsGlobal, true);
    Assert.assertEquals(1, userPerms.size());
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsFile, false);
    Assert.assertEquals(1, userPerms.size());
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsFile, WRITE)));
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsTmp, true);
    Assert.assertEquals(0, userPerms.size());
  
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsGlobal, false);
    Assert.assertEquals(1, groupPerms.size());
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsFile, true);
    Assert.assertEquals(1, groupPerms.size());
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsFile, WRITE)));
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsTmp, true);
    Assert.assertEquals(0, groupPerms.size());
  
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsGlobal, true);
    Assert.assertEquals(1, rolePerms.size());
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsFile, true);
    Assert.assertEquals(1, rolePerms.size());
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsFile, WRITE)));
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsTmp, true);
    Assert.assertEquals(0, rolePerms.size());
  
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), true);
    //Assert.assertEquals(3, userPerms.size());
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    Assert.assertTrue(userPerms.contains(new PermVo(hdfsFile, WRITE)));
    Assert.assertTrue(userPerms.contains(new PermVo(yarnDep, DELETE)));
  
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), false);
    Assert.assertEquals(3, groupPerms.size());
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    Assert.assertTrue(groupPerms.contains(new PermVo(hdfsFile, WRITE)));
    Assert.assertTrue(groupPerms.contains(new PermVo(yarnDep, DELETE)));
  
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), false);
    Assert.assertEquals(3, rolePerms.size());
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION)));
    Assert.assertTrue(rolePerms.contains(new PermVo(hdfsFile, WRITE)));
    Assert.assertTrue(rolePerms.contains(new PermVo(yarnDep, DELETE)));
  
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalAdmin));
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalAdmin, true));
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsFileWrite));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsFileWrite, true));
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsFileWrite));
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), yarnDepDelete));
  
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsGlobalAdmin, false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsFileWrite, false));
    Assert.assertTrue(guardianClient.checkAccess(userVo.getUsername(), yarnDepDelete, false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsTmpRead, false));
  
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), true));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
  
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertTrue(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsTmpRead, yarnGlobalAdmin, yarnDefaultSubmit), false));
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(USER, hdfsGlobalAdmin, true);
    Assert.assertEquals(0, hdfsGlobalAdminPrincs.size());
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(USER, yarnDepDelete, true);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.userPerm(userVo.getUsername(), yarnDepDelete, false)));
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, hdfsGlobalAdmin, true);
    Assert.assertEquals(0, hdfsGlobalAdminPrincs.size());
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, yarnDepDelete, true);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.groupPerm(groupVo.getGroupName(), yarnDepDelete, false)));
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, hdfsGlobalAdmin, true);
    Assert.assertEquals(0, hdfsGlobalAdminPrincs.size());
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, yarnDepDelete, false);
    Assert.assertEquals(1, yarnDepDeletePrincs.size());
    Assert.assertTrue(yarnDepDeletePrincs.contains(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnDepDelete, false)));
  
    userAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.user(userVo.getUsername()), PREFIX + "hdfs1", true);
    Assert.assertEquals(0, userAuthorizedResources.size());
  
    groupAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.group(groupVo.getGroupName()), PREFIX + "hdfs1", true);
    Assert.assertEquals(0, groupAuthorizedResources.size());
  
    roleAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.role(roleVo.getRoleName()), PREFIX + "yarn1", false);
    Assert.assertEquals(1, roleAuthorizedResources.size());
    Assert.assertTrue(roleAuthorizedResources.contains(new ResourceVo.Builder().dataSource(yarnDep.getDataSource()).build()));
  
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsGlobal, true);
    Assert.assertEquals(0, userPerms.size());
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsFile, false);
    Assert.assertEquals(0, userPerms.size());
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsTmp, true);
    Assert.assertEquals(0, userPerms.size());
  
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsGlobal, false);
    Assert.assertEquals(0, groupPerms.size());
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsFile, true);
    Assert.assertEquals(0, groupPerms.size());
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsTmp, true);
    Assert.assertEquals(0, groupPerms.size());
  
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsGlobal, true);
    Assert.assertEquals(0, rolePerms.size());
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsFile, true);
    Assert.assertEquals(0, rolePerms.size());
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsTmp, true);
    Assert.assertEquals(0, rolePerms.size());
  
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), false);
    Assert.assertEquals(0, userPerms.size());
  
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), false);
    Assert.assertEquals(1, groupPerms.size());
    Assert.assertTrue(groupPerms.contains(new PermVo(yarnDep, DELETE)));
  
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), false);
    Assert.assertEquals(1, rolePerms.size());
    Assert.assertTrue(rolePerms.contains(new PermVo(yarnDep, DELETE)));
  
    guardianClient.deletePerm(hdfsGlobalAdmin);
    guardianClient.deletePerm(hdfsTmpRead);
    guardianClient.deletePerm(hdfsFileWrite);
    guardianClient.deletePerm(yarnGlobalAdmin);
    guardianClient.deletePerm(yarnDefaultSubmit);
    guardianClient.deletePerm(yarnDepDelete);
  
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsGlobalAdmin, true));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsFileWrite, true));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), yarnDepDelete, false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), hdfsTmpRead, false));
  
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), true));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertFalse(guardianClient.checkAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
  
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), true));
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsFileWrite, yarnDepDelete), false));
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsGlobalAdmin, hdfsTmpRead, hdfsFileWrite), false));
    Assert.assertFalse(guardianClient.checkAnyAccess(userVo.getUsername(), Arrays.asList(hdfsTmpRead, yarnGlobalAdmin, yarnDefaultSubmit), false));
  
    hdfsRootChildren = guardianClient.getChildNodes(hdfsRoot);
    Assert.assertEquals(2, hdfsRootChildren.size());
    Assert.assertTrue(hdfsRootChildren.contains(new NodeVo(DIR, "tmp")));
    Assert.assertTrue(hdfsRootChildren.contains(new NodeVo(FILE, "aaa")));
  
    yarnRootChildren = guardianClient.getChildNodes(yarnRoot);
    Assert.assertEquals(2, yarnRootChildren.size());
    Assert.assertTrue(yarnRootChildren.contains(new NodeVo(QUEUE, "idc")));
    Assert.assertTrue(yarnRootChildren.contains(new NodeVo(QUEUE, "default")));
  
    yarnRootDescendants = guardianClient.getDescendantResources(yarnRoot);
    Assert.assertEquals(2, yarnRootDescendants.size());
    Assert.assertTrue(yarnRootDescendants.contains(yarnDefault));
    Assert.assertTrue(yarnRootDescendants.contains(yarnDep));
  
    yarnDescendants = guardianClient.getDescendantResources(yarnGlobal.service().build());
    Assert.assertEquals(3, yarnDescendants.size());
    Assert.assertTrue(yarnDescendants.contains(yarnGlobal));
    Assert.assertTrue(yarnDescendants.contains(yarnDefault));
    Assert.assertTrue(yarnDescendants.contains(yarnDep));
  
    hdfsRootPermActions = guardianClient.getResourcePermActions(hdfsRoot);
    Assert.assertTrue(hdfsRootPermActions.isEmpty());
    hdfsTmpPermActions = guardianClient.getResourcePermActions(hdfsTmp);
    Assert.assertTrue(hdfsTmpPermActions.isEmpty());
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(USER, hdfsGlobalAdmin, false);
    Assert.assertTrue(hdfsGlobalAdminPrincs.isEmpty());
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(USER, yarnDepDelete, true);
    Assert.assertTrue(yarnDepDeletePrincs.isEmpty());
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, hdfsGlobalAdmin, false);
    Assert.assertTrue(hdfsGlobalAdminPrincs.isEmpty());
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.GROUP, yarnDepDelete, true);
    Assert.assertTrue(yarnDepDeletePrincs.isEmpty());
  
    hdfsGlobalAdminPrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, hdfsGlobalAdmin, true);
    Assert.assertTrue(hdfsGlobalAdminPrincs.isEmpty());
    yarnDepDeletePrincs = guardianClient.getAuthorizedPrincs(PrincipalType.ROLE, yarnDepDelete, false);
    Assert.assertTrue(yarnDepDeletePrincs.isEmpty());
  
    userAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.user(userVo.getUsername()), PREFIX + "hdfs1", true);
    Assert.assertEquals(0, userAuthorizedResources.size());
  
    groupAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.group(groupVo.getGroupName()), PREFIX + "hdfs1", true);
    Assert.assertEquals(0, groupAuthorizedResources.size());
  
    roleAuthorizedResources = guardianClient.getAuthorizedResources(PrincipalVo.role(roleVo.getRoleName()), PREFIX + "yarn1", false);
    Assert.assertEquals(0, roleAuthorizedResources.size());
  
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsGlobal, true);
    Assert.assertEquals(0, userPerms.size());
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsFile, false);
    Assert.assertEquals(0, userPerms.size());
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsTmp, true);
    Assert.assertEquals(0, userPerms.size());
  
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsGlobal, true);
    Assert.assertEquals(0, groupPerms.size());
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsFile, true);
    Assert.assertEquals(0, groupPerms.size());
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsTmp, true);
    Assert.assertEquals(0, groupPerms.size());
  
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsGlobal, true);
    Assert.assertEquals(0, rolePerms.size());
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsFile, true);
    Assert.assertEquals(0, rolePerms.size());
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsTmp, true);
    Assert.assertEquals(0, rolePerms.size());
  
    userPerms = guardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), false);
    Assert.assertEquals(0, userPerms.size());
  
    groupPerms = guardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), true);
    Assert.assertEquals(0, groupPerms.size());
  
    rolePerms = guardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), false);
    Assert.assertEquals(0, rolePerms.size());
  
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteRole(roleVo.getRoleName());
    guardianClient.deleteGroup(groupVo.getGroupName());
    guardianClient.deleteServiceResource(PREFIX + "hdfs1");
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
  }

  @Test
  public void testDeleteServicePerms() throws GuardianClientException {
    PermVo perm1 = new PermVo(hdfsTmp, READ);
    PermVo perm2 = new PermVo(hdfsFile, EXEC);
    guardianClient.addPerm(perm1);
    guardianClient.addPerm(perm2);
    List<PermActionVo> permActionVos = guardianClient.getResourcePermActions(hdfsTmp);
    Assert.assertEquals(1, permActionVos.size());
    permActionVos = guardianClient.getResourcePermActions(hdfsFile);
    Assert.assertEquals(1, permActionVos.size());

    guardianClient.deleteServicePerms(hdfsTmp.getServiceName());
    permActionVos = guardianClient.getResourcePermActions(hdfsTmp);
    Assert.assertTrue(permActionVos == null || permActionVos.isEmpty());
    permActionVos = guardianClient.getResourcePermActions(hdfsFile);
    Assert.assertTrue(permActionVos == null || permActionVos.isEmpty());

    guardianClient.deleteServiceResource(hdfsTmp.getServiceName());
  }
  
  @Test
  public void testDeleteResourcePerms() throws GuardianClientException {
    PermVo perm1 = new PermVo(hdfsTmp, READ);
    PermVo perm2 = new PermVo(hdfsTmp, WRITE);
  
    guardianClient.addPerm(perm1);
    guardianClient.addPerm(perm2);
  
    guardianClient.deleteResourcePerms(hdfsTmp);
  
    List<PermActionVo> permActionVos = guardianClient.getResourcePermActions(hdfsTmp);
    Assert.assertTrue(permActionVos == null || permActionVos.isEmpty());
  
    List<ResourceVo> descendants = guardianClient.getDescendantResources(hdfsTmp.service().build());
    Assert.assertEquals(1, descendants.size());
    
    guardianClient.deleteServiceResource(hdfsTmp.getServiceName());
  }
  
  @Test
  public void testGetResourcePrincPerms() throws GuardianException {
    PermVo perm1 = new PermVo(hdfsTmp, READ);
    PermVo perm2 = new PermVo(hdfsTmp, WRITE);
    PermVo perm3 = new PermVo(hdfsTmp, SUBMIT);
    
    for (int i = 0; i < 10; i++) {
      guardianClient.addUser(new UserVo(PREFIX + "u" + i, "123"));
      guardianClient.addGroup(new GroupVo(PREFIX + "g" + i));
      guardianClient.addRole(new RoleVo(PREFIX + "r" + i));
    }
    
    PrincGroupVo u1g0 = PrincGroupVo.userGroup(PREFIX + "u1", new GroupVo(PREFIX + "g0"));
    guardianClient.assignGroup(u1g0);
    PrincGroupVo u4g0 = PrincGroupVo.userGroup(PREFIX + "u4", new GroupVo(PREFIX + "g0"));
    guardianClient.assignGroup(u4g0);
    PrincGroupVo u3g1 = PrincGroupVo.userGroup(PREFIX + "u3", new GroupVo(PREFIX + "g1"));
    guardianClient.assignGroup(u3g1);
    PrincGroupVo u7g1 = PrincGroupVo.userGroup(PREFIX + "u7", new GroupVo(PREFIX + "g1"));
    guardianClient.assignGroup(u7g1);
    PrincGroupVo u5g2 = PrincGroupVo.userGroup(PREFIX + "u5", new GroupVo(PREFIX + "g2"));
    guardianClient.assignGroup(u5g2);
    PrincGroupVo u9g3 = PrincGroupVo.userGroup(PREFIX + "u9", new GroupVo(PREFIX + "g3"));
    guardianClient.assignGroup(u9g3);
    
    UserRoleVo u2r0 = new UserRoleVo(PREFIX + "u2", PREFIX + "r0");
    guardianClient.assignRole(u2r0);
    UserRoleVo u6r0 = new UserRoleVo(PREFIX + "u6", PREFIX + "r0");
    guardianClient.assignRole(u6r0);
    
    GroupRoleVo g1r0 = new GroupRoleVo(PREFIX + "g1", PREFIX + "r0");
    guardianClient.assignRole(g1r0);
    GroupRoleVo g3r1 = new GroupRoleVo(PREFIX + "g3", PREFIX + "r1");
    guardianClient.assignRole(g3r1);
    
    guardianClient.grantPerm(PrincPermVo.userPerm(PREFIX + "u0", perm1));
    guardianClient.grantPerm(PrincPermVo.userPerm(PREFIX + "u9", perm1));
    guardianClient.grantPerm(PrincPermVo.groupPerm(PREFIX + "g3", perm1));
    guardianClient.grantPerm(PrincPermVo.rolePerm(PREFIX + "r1", perm1, true));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(PREFIX + "u5", perm2));
    guardianClient.grantPerm(PrincPermVo.userPerm(PREFIX + "u4", perm2, true));
    guardianClient.grantPerm(PrincPermVo.groupPerm(PREFIX + "g0", perm2));
    guardianClient.grantPerm(PrincPermVo.groupPerm(PREFIX + "g2", perm2, true));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(PREFIX + "u6", perm3, true));
    guardianClient.grantPerm(PrincPermVo.userPerm(PREFIX + "u7", perm3, true));
    guardianClient.grantPerm(PrincPermVo.rolePerm(PREFIX + "r0", perm3));
    
    List<PrincPermVo> princPerms = guardianClient.getResourcePerms(hdfsTmp, false);
    Assert.assertEquals(11, princPerms.size());
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u0", new PermVo(hdfsTmp, READ))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u9", new PermVo(hdfsTmp, READ))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u4", new PermVo(hdfsTmp, WRITE), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u5", new PermVo(hdfsTmp, WRITE))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u6", new PermVo(hdfsTmp, SUBMIT), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u7", new PermVo(hdfsTmp, SUBMIT), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.groupPerm(PREFIX + "g3", new PermVo(hdfsTmp, READ))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.groupPerm(PREFIX + "g0", new PermVo(hdfsTmp, WRITE))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.groupPerm(PREFIX + "g2", new PermVo(hdfsTmp, WRITE), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.rolePerm(PREFIX + "r1", new PermVo(hdfsTmp, READ), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.rolePerm(PREFIX + "r0", new PermVo(hdfsTmp, SUBMIT))));
    
    princPerms = guardianClient.getResourcePerms(hdfsTmp, true);
    Assert.assertEquals(15, princPerms.size());
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u0", new PermVo(hdfsTmp, READ))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u9", new PermVo(hdfsTmp, READ), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u4", new PermVo(hdfsTmp, WRITE), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u5", new PermVo(hdfsTmp, WRITE), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u1", new PermVo(hdfsTmp, WRITE))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u2", new PermVo(hdfsTmp, SUBMIT))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u3", new PermVo(hdfsTmp, SUBMIT))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u6", new PermVo(hdfsTmp, SUBMIT), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.userPerm(PREFIX + "u7", new PermVo(hdfsTmp, SUBMIT), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.groupPerm(PREFIX + "g3", new PermVo(hdfsTmp, READ), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.groupPerm(PREFIX + "g0", new PermVo(hdfsTmp, WRITE))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.groupPerm(PREFIX + "g2", new PermVo(hdfsTmp, WRITE), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.groupPerm(PREFIX + "g1", new PermVo(hdfsTmp, SUBMIT))));
    Assert.assertTrue(princPerms.contains(PrincPermVo.rolePerm(PREFIX + "r1", new PermVo(hdfsTmp, READ), true)));
    Assert.assertTrue(princPerms.contains(PrincPermVo.rolePerm(PREFIX + "r0", new PermVo(hdfsTmp, SUBMIT))));
  
    for (int i = 0; i < 10; i++) {
      guardianClient.deleteUser(PREFIX + "u" + i);
      guardianClient.deleteGroup(PREFIX + "g" + i);
      guardianClient.deleteRole(PREFIX + "r" + i);
    }
    guardianClient.deleteServiceResource(hdfsTmp.getServiceName());
  }
  
  // super-admin
  // perm-admin
  // global admin
  // datasource admin
  // grant perm to user
  @Test
  public void addDeletePermAuthTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    
    PermVo hdfsGlobalAdmin = new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsGlobalExec = new PermVo(hdfsGlobal, EXEC);
    PermVo hdfsRootAdmin = new PermVo(hdfsRoot, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsTmpAdmin = new PermVo(hdfsTmp, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsTmpRead = new PermVo(hdfsTmp, READ);
    
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    GuardianClientV2 userGuardianClient = GuardianClientV2Factory.getInstance(configuration);
    
    try {
      userGuardianClient.addPerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.deletePerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.addPerm(hdfsTmpRead);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.deletePerm(hdfsTmpRead);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.addPerm(hdfsGlobalExec);
    userGuardianClient.addPerm(hdfsTmpRead);
    userGuardianClient.deletePerm(hdfsGlobalExec);
    userGuardianClient.deletePerm(hdfsTmpRead);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.addPerm(hdfsGlobalExec);
    userGuardianClient.addPerm(hdfsTmpRead);
    userGuardianClient.deletePerm(hdfsGlobalExec);
    userGuardianClient.deletePerm(hdfsTmpRead);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.addPerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.deletePerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.addPerm(hdfsTmpRead);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.deletePerm(hdfsTmpRead);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    userGuardianClient.addPerm(hdfsGlobalExec);
    userGuardianClient.addPerm(hdfsTmpRead);
    userGuardianClient.deletePerm(hdfsGlobalExec);
    userGuardianClient.deletePerm(hdfsTmpRead);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootAdmin));
    try {
      userGuardianClient.addPerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.deletePerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    userGuardianClient.addPerm(hdfsTmpRead);
    userGuardianClient.deletePerm(hdfsTmpRead);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootAdmin));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpAdmin));
    try {
      userGuardianClient.addPerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.deletePerm(hdfsGlobalExec);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    userGuardianClient.addPerm(hdfsTmpRead);
    userGuardianClient.deletePerm(hdfsTmpRead);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpAdmin));
    
    guardianClient.deleteServiceResource(PREFIX + "hdfs1");
    guardianClient.deleteUser(userVo.getUsername());
  }
  
  // super-admin
  // perm-admin
  // global admin
  // datasource admin
  // global perm with grant option
  // datasource perm with grant option
  // grant perm to group
  @Test
  public void grantRevokePermAuthTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    GroupVo groupVo = new GroupVo(PREFIX + "g");
    guardianClient.addGroup(groupVo);
    guardianClient.assignGroup(PrincGroupVo.userGroup(userVo.getUsername(), groupVo));
    
    UserVo objectUser = new UserVo(PREFIX + "objectUser", "123");
    guardianClient.addUser(objectUser);
  
    PermVo hdfsGlobalAdmin = new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsGlobalExec = new PermVo(hdfsGlobal, EXEC);
    PermVo hdfsRootAdmin = new PermVo(hdfsRoot, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsRootRead = new PermVo(hdfsRoot, READ);
    PermVo hdfsTmpAdmin = new PermVo(hdfsTmp, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsTmpRead = new PermVo(hdfsTmp, READ);
  
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    GuardianClientV2 userGuardianClient = GuardianClientV2Factory.getInstance(configuration);
    
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalAdmin));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalAdmin));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalExec));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalExec));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalExec, true));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsGlobalExec));
    
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsRootAdmin));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsRootAdmin));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsTmpAdmin));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsTmpAdmin));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsTmpRead));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsTmpRead));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsTmpRead, true));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsTmpRead));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsRootRead, true));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsRootRead));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), new PermVo(hdfsGlobal, READ), true));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), new PermVo(hdfsGlobal, READ)));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), new PermVo(hdfsGlobal, READ)));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), new PermVo(hdfsGlobal, READ)));
  
    guardianClient.grantPerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsRootRead));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsTmpRead));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.revokePerm(PrincPermVo.userPerm(objectUser.getUsername(), hdfsGlobalExec));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.groupPerm(groupVo.getGroupName(), hdfsRootRead));
    
    guardianClient.deleteServiceResource(PREFIX + "hdfs1");
    guardianClient.deleteUser(objectUser.getUsername());
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteGroup(groupVo.getGroupName());
  }
  
  // super-admin
  // perm-admin
  // global admin
  // datasource admin
  // grant perm to role
  @Test
  public void grantNewPermTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    RoleVo roleVo = new RoleVo(PREFIX + "r");
    guardianClient.addRole(roleVo);
    guardianClient.assignRole(new UserRoleVo(userVo.getUsername(), roleVo.getRoleName()));
  
    UserVo objectUser = new UserVo(PREFIX + "objectUser", "123");
    guardianClient.addUser(objectUser);
  
    PermVo yarnGlobalAdmin = new PermVo(yarnGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo yarnRootAdmin = new PermVo(yarnRoot, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo yarnRootDelete = new PermVo(yarnRoot, DELETE);
    PermVo yarnDepAdmin = new PermVo(yarnDep, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo yarnDepDelete = new PermVo(yarnDep, DELETE);
  
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    GuardianClientV2 userGuardianClient = GuardianClientV2Factory.getInstance(configuration);
  
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnGlobalAdmin));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnGlobalAdmin));
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnRootAdmin));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnRootAdmin));
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnDepAdmin));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnDepAdmin));
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
    
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnRootDelete, true));
    userGuardianClient.grantPerm(PrincPermVo.userPerm(objectUser.getUsername(), yarnDepDelete));
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), yarnDepDelete));
    guardianClient.deleteServiceResource(PREFIX + "yarn1");
    
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteRole(roleVo.getRoleName());
    guardianClient.deleteUser(objectUser.getUsername());
  }
  
  // super-admin
  // perm-admin
  // global admin
  // datasource admin
  // grant perm to role inherited by group
  @Test
  public void getPermActionAuthTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    GroupVo groupVo = new GroupVo(PREFIX + "g");
    guardianClient.addGroup(groupVo);
    RoleVo roleVo = new RoleVo(PREFIX + "r");
    guardianClient.addRole(roleVo);
    guardianClient.assignRole(new GroupRoleVo(groupVo.getGroupName(), roleVo.getRoleName()));
    guardianClient.assignGroup(PrincGroupVo.userGroup(userVo.getUsername(), groupVo));
  
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    GuardianClientV2 userGuardianClient = GuardianClientV2Factory.getInstance(configuration);
    
    try {
      userGuardianClient.getResourcePermActions(hdfsTmp);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.getResourcePermActions(hdfsTmp);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.getResourcePermActions(hdfsTmp);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.getResourcePermActions(hdfsTmp);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    
    PermVo hdfsTmpAdmin = new PermVo(hdfsTmp, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsTmpRead = new PermVo(hdfsTmp, READ);
    PermVo hdfsGlobalAdmin = new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsGlobalRead = new PermVo(hdfsGlobal, READ);
    PermVo hdfsRootAdmin = new PermVo(hdfsRoot, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsRootRead = new PermVo(hdfsRoot, READ);
    
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsTmpAdmin));
    userGuardianClient.getResourcePermActions(hdfsTmp);
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsTmpAdmin));
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsTmpRead));
    try {
      userGuardianClient.getResourcePermActions(hdfsTmp);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsTmpRead));
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalAdmin));
    userGuardianClient.getResourcePermActions(hdfsTmp);
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalAdmin));
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalRead));
    try {
      userGuardianClient.getResourcePermActions(hdfsTmp);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsGlobalRead));
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsRootAdmin));
    userGuardianClient.getResourcePermActions(hdfsTmp);
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsRootAdmin));
  
    guardianClient.grantPerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsRootRead));
    try {
      userGuardianClient.getResourcePermActions(hdfsTmp);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.rolePerm(roleVo.getRoleName(), hdfsRootRead));
    
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteGroup(groupVo.getGroupName());
    guardianClient.deleteRole(roleVo.getRoleName());
    guardianClient.deleteServiceResource(PREFIX + "hdfs1");
  }
  
  // super-admin
  // perm-admin
  // global admin
  // datasource admin
  // grant perm to user
  @Test
  public void getAuthorizedPrincAuthTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    GuardianClientV2 userGuardianClient = GuardianClientV2Factory.getInstance(configuration);
  
    PermVo hdfsTmpAdmin = new PermVo(hdfsTmp, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsTmpRead = new PermVo(hdfsTmp, READ);
    PermVo hdfsGlobalAdmin = new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsGlobalRead = new PermVo(hdfsGlobal, READ);
    PermVo hdfsRootAdmin = new PermVo(hdfsRoot, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsRootRead = new PermVo(hdfsRoot, READ);
    
    try {
      userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpAdmin));
    userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpAdmin));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpRead));
    try {
      userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpRead));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalRead));
    try {
      userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalRead));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootAdmin));
    userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootAdmin));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootRead));
    try {
      userGuardianClient.getAuthorizedPrincs(USER, hdfsTmpRead, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootRead));
    
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteServiceResource(PREFIX + "hdfs1");
  }
  
  // super-admin
  // perm-admin
  // global admin
  // is requested user
  // has requested group
  // has requested role
  @Test
  public void getAuthorizedResourceAuthTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    GroupVo groupVo = new GroupVo(PREFIX + "g");
    guardianClient.addGroup(groupVo);
    RoleVo roleVo = new RoleVo(PREFIX + "r");
    guardianClient.addRole(roleVo);
    guardianClient.assignRole(new GroupRoleVo(groupVo.getGroupName(), roleVo.getRoleName()));
    guardianClient.assignGroup(PrincGroupVo.userGroup(userVo.getUsername(), groupVo));
  
    UserVo requestUser = new UserVo(PREFIX + "requestUser", "123");
    guardianClient.addUser(requestUser);
    RoleVo requestRole = new RoleVo(PREFIX + "requestRole");
    guardianClient.addRole(requestRole);
    GroupVo requestGroup = new GroupVo(PREFIX + "requestGroup");
    guardianClient.addGroup(requestGroup);
    
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    GuardianClientV2 userGuardianClient = GuardianClientV2Factory.getInstance(configuration);
  
    PermVo hdfsGlobalAdmin = new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    
    userGuardianClient.getAuthorizedResources(PrincipalVo.user(userVo.getUsername()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.group(groupVo.getGroupName()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.role(roleVo.getRoleName()), PREFIX + "hdfs1", true);
  
    try {
      userGuardianClient.getAuthorizedResources(PrincipalVo.user(requestUser.getUsername()), PREFIX + "hdfs1", true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getAuthorizedResources(PrincipalVo.group(requestGroup.getGroupName()), PREFIX + "hdfs1", true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getAuthorizedResources(PrincipalVo.role(requestRole.getRoleName()), PREFIX + "hdfs1", true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.getAuthorizedResources(PrincipalVo.user(requestUser.getUsername()), PREFIX + "hdfs1", true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getAuthorizedResources(PrincipalVo.group(requestGroup.getGroupName()), PREFIX + "hdfs1", true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getAuthorizedResources(PrincipalVo.role(requestRole.getRoleName()), PREFIX + "hdfs1", true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.getAuthorizedResources(PrincipalVo.user(requestUser.getUsername()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.group(requestGroup.getGroupName()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.role(requestRole.getRoleName()), PREFIX + "hdfs1", true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.getAuthorizedResources(PrincipalVo.user(requestUser.getUsername()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.group(requestGroup.getGroupName()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.role(requestRole.getRoleName()), PREFIX + "hdfs1", true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    userGuardianClient.getAuthorizedResources(PrincipalVo.user(requestUser.getUsername()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.group(requestGroup.getGroupName()), PREFIX + "hdfs1", true);
    userGuardianClient.getAuthorizedResources(PrincipalVo.role(requestRole.getRoleName()), PREFIX + "hdfs1", true);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteUser(requestUser.getUsername());
    guardianClient.deleteGroup(groupVo.getGroupName());
    guardianClient.deleteGroup(requestGroup.getGroupName());
    guardianClient.deleteRole(roleVo.getRoleName());
    guardianClient.deleteRole(requestRole.getRoleName());
  }
  
  
  // super-admin
  // perm-admin
  // global admin
  // datasource admin
  // is request user
  // has request group
  // has request role
  @Test
  public void getPrincPermAuthTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    GroupVo groupVo = new GroupVo(PREFIX + "g");
    guardianClient.addGroup(groupVo);
    RoleVo roleVo = new RoleVo(PREFIX + "r");
    guardianClient.addRole(roleVo);
    guardianClient.assignRole(new GroupRoleVo(groupVo.getGroupName(), roleVo.getRoleName()));
    guardianClient.assignGroup(PrincGroupVo.userGroup(userVo.getUsername(), groupVo));
  
    UserVo requestUser = new UserVo(PREFIX + "requestUser", "123");
    guardianClient.addUser(requestUser);
    RoleVo requestRole = new RoleVo(PREFIX + "requestRole");
    guardianClient.addRole(requestRole);
    GroupVo requestGroup = new GroupVo(PREFIX + "requestGroup");
    guardianClient.addGroup(requestGroup);
  
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    GuardianClientV2 userGuardianClient = GuardianClientV2Factory.getInstance(configuration);
  
    PermVo hdfsGlobalAdmin = new PermVo(hdfsGlobal, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsGlobalRead = new PermVo(hdfsGlobal, READ);
    PermVo hdfsRootAdmin = new PermVo(hdfsRoot, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsRootRead = new PermVo(hdfsRoot, READ);
    PermVo hdfsTmpAdmin = new PermVo(hdfsTmp, GuardianConstants.ADMIN_PERM_ACTION);
    PermVo hdfsTmpRead = new PermVo(hdfsTmp, READ);
  
    userGuardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), hdfsTmp, true);
  
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
  
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
    userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalAdmin));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalRead));
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsGlobalRead));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootAdmin));
    userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootAdmin));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootRead));
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsRootRead));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpAdmin));
    userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpAdmin));
  
    guardianClient.grantPerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpRead));
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), hdfsTmp, true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.revokePerm(PrincPermVo.userPerm(userVo.getUsername(), hdfsTmpRead));
  
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteUser(requestUser.getUsername());
    guardianClient.deleteGroup(groupVo.getGroupName());
    guardianClient.deleteGroup(requestGroup.getGroupName());
    guardianClient.deleteRole(roleVo.getRoleName());
    guardianClient.deleteRole(requestRole.getRoleName());
  }
  
  
  // super-admin
  // perm-admin
  // is request user
  // has request group
  // has request role
  @Test
  public void getPrincAllPermAuthTest() throws GuardianClientException {
    UserVo userVo = new UserVo(PREFIX + "u", "123");
    guardianClient.addUser(userVo);
    GroupVo groupVo = new GroupVo(PREFIX + "g");
    guardianClient.addGroup(groupVo);
    RoleVo roleVo = new RoleVo(PREFIX + "r");
    guardianClient.addRole(roleVo);
    guardianClient.assignRole(new GroupRoleVo(groupVo.getGroupName(), roleVo.getRoleName()));
    guardianClient.assignGroup(PrincGroupVo.userGroup(userVo.getUsername(), groupVo));
    
    UserVo requestUser = new UserVo(PREFIX + "requestUser", "123");
    guardianClient.addUser(requestUser);
    RoleVo requestRole = new RoleVo(PREFIX + "requestRole");
    guardianClient.addRole(requestRole);
    GroupVo requestGroup = new GroupVo(PREFIX + "requestGroup");
    guardianClient.addGroup(requestGroup);
    
    GuardianConfiguration configuration = new GuardianConfiguration();
    configuration.set(GuardianVars.GUARDIAN_CLIENT_CACHE_ENABLED.varname, "false");
    configuration.set(GuardianVars.GUARDIAN_CLIENT_AUTH_MODE.varname, "PLAIN");
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_USERNAME.varname, userVo.getUsername());
    configuration.set(GuardianVars.GUARDIAN_CONNECTION_PASSWORD.varname, userVo.getUserPassword());
    // use a new instance here to create a new sessionVo by force at server side
    GuardianClientV2 userGuardianClient = new GuardianClientV2RestImpl(configuration);
    
    userGuardianClient.getPrincPerms(PrincipalVo.user(userVo.getUsername()), true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(groupVo.getGroupName()), true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(roleVo.getRoleName()), true);
    
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    try {
      userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), true);
      Assert.fail();
    } catch (GuardianClientException e) {
      Assert.assertEquals(ErrorCodes.AUTHORIZED_FAILURE, e.getReturnCode());
    }
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.USER_ADMIN_ROLE));
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.SUPER_ADMIN_ROLE));
    
    guardianClient.assignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    userGuardianClient.getPrincPerms(PrincipalVo.user(requestUser.getUsername()), true);
    userGuardianClient.getPrincPerms(PrincipalVo.group(requestGroup.getGroupName()), true);
    userGuardianClient.getPrincPerms(PrincipalVo.role(requestRole.getRoleName()), true);
    guardianClient.deassignAdminRole(new UserAdminRoleVo(userVo.getUsername(), GuardianConstants.PERM_ADMIN_ROLE));
    
    guardianClient.deleteUser(userVo.getUsername());
    guardianClient.deleteUser(requestUser.getUsername());
    guardianClient.deleteGroup(groupVo.getGroupName());
    guardianClient.deleteGroup(requestGroup.getGroupName());
    guardianClient.deleteRole(roleVo.getRoleName());
    guardianClient.deleteRole(requestRole.getRoleName());
  }
}
