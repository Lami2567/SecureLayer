package com.securelayer.core.api;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.securelayer.core.config.SecurityConfig;
import com.securelayer.core.domain.Tenant;
import com.securelayer.core.service.AdminService;
import com.securelayer.core.service.DeviceIdentityService;
import com.securelayer.core.service.PolicyEngineService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@WebMvcTest(AdminController.class)
@Import(SecurityConfig.class)
class AdminControllerIntegrationTest {
    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private AdminService adminService;

    @MockitoBean
    private DeviceIdentityService deviceIdentityService;

    @MockitoBean
    private PolicyEngineService policyEngineService;

    @Test
    void superAdminCanCreateTenant() throws Exception {
        Tenant tenant = new Tenant("acme");
        ReflectionTestUtils.setField(tenant, "id", UUID.randomUUID());
        when(adminService.createTenant(any())).thenReturn(tenant);

        mvc.perform(post("/api/v1/admin/tenants")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")))
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"name\":\"acme\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void developerCannotCreateTenant() throws Exception {
        mvc.perform(post("/api/v1/admin/tenants")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_DEVELOPER")))
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"name\":\"acme\"}"))
                .andExpect(status().isForbidden());
    }
}
