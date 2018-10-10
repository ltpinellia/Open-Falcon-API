请求方式          URI                                                 说明                            是否封装           请求                               
PATCH  /api/v1/hostgroup/#{hostgroup_id}/host           Update partial hosts in HostGroup              是
PUT    /api/v1/user/update                              Update User                                    是
GET    /api/v1/user/logout                              Logout                                         是
POST   /api/v1/user/login                               Login                                          是
GET    /api/v1/user/users                               User List                                      是
GET    /api/v1/user/u/:uid/in_teams                     Check user in teams or not                     是
GET    /api/v1/user/u/:uid/teams                        Get user teams                                 是
GET    /api/v1/user/name/#{user_name}                   Get User info by name                          是
GET    /api/v1/user/u/#{user_id}                        Get User info by id                            是
GET    /api/v1/user/current                             Current User info                              是
POST   /api/v1/user/create                              Create User                                    是
PUT    /api/v1/user/cgpasswd                            Change Password                                是                           
PUT    /api/v1/template/                                Update Template                                是
GET    /api/v1/template                                 Template List                                  是
GET    /api/v1/template/#{template_id}                  Get Template Info by id                        是
GET    /api/v1/template/#{template_id}/hostgroup        Get hostgroups list by id                      是
DELETE /api/v1/template/#{template_id}                  Delete Template                                是
POST   /api/v1/template                                 Create Template                                是
PUT    /api/v1/template/action                          Update Template Action                         是
POST   /api/v1/template/action                          Create Template Action                         是
PUT    /api/v1/team                                     Team Update                                    是
GET    /api/v1/team                                     Team List                                      是
GET    /api/v1/team/name/#{team_name}                   Get Team Info by name                          是
GET    /api/v1/team/t/#{team_id}                        Get Team Info By Id                            是
DELETE /api/v1/team/#{team_id}                          Delete Team By Id                              是
POST   /api/v1/team                                     Team Create                                    是
PUT    /api/v1/strategy                                 Update Strategy                                是
GET    /api/v1/strategy                                 Get Strategy List                              是
GET    /api/v1/strategy/#{strategy_id}                  Get Strategy info by id                        是 
DELETE /api/v1/strategy/#{strategy_id}                  Delete Strategy                                是
POST   /api/v1/strategy                                 Create Strategy                                是 
GET    /api/v1/metric/default_list                      Get Default Builtin Metric List                是
GET    /api/v1/hostgroup/#{hostgroup_id}/plugins        Get Plugin List of HostGroup                   是
DELETE /api/v1/plugin/#{plugin_id}                      Delete Plugin                                  是
POST   /api/v1/plugin                                   Create A Plugin of HostGroup                   是
PUT    /api/v1/nodata/                                  Update Nodata                                  是
GET    /api/v1/nodata                                   Nodata List                                    是
GET    /api/v1/nodata/#{nodata_id}                      Get Nodata Info by id                          是
DELETE /api/v1/nodata/#{nodata_id}                      Delete Nodata                                  是
POST   /api/v1/nodata/                                  Create Nodata                                  是
PUT    /api/v1/hostgroup/update/#{hostgroup_id}         Update HostGroup info by id                    有问题
PUT    /api/v1/hostgroup/host                           Unbind a Host on HostGroup                     是
PUT    /api/v1/hostgroup/template                       Unbind A Template of A HostGroup               是
GET    /api/v1/hostgroup/#{hostgroup_id}/template       Get Template List of HostGroup                 是
POST   /api/v1/hostgroup/template                       Bind A Template to HostGroup                   是
GET    /api/v1/hostgroup                                HostGroup List                                 是
GET    /api/v1/hostgroup/#{hostgroup_id}                Get HostGroup info by id                       是
DELETE /api/v1/hostgroup/#{hostgroup_id}                Delete HostGroup                               是
POST   /api/v1/hostgroup                                Create HostGroup                               是
POST   /api/v1/hostgroup/host                           Add Hosts to HostGroup                         是
DELETE /api/v1/host/maintain                            Reset host maintain by ids or hostnames        是
GET    /api/v1/host/#{host_id}/template                 Get bind Template List of Host                 是
GET    /api/v1/host/#{host_id}/hostgroup                Get related HostGorup of Host                  是
POST   /api/v1/host/maintain                            Set host maintain by ids or hostnames          是
POST   /api/v1/graph/history                            Graph History                                  是
POST   /v1/grafana/render                               Grafan query                                   不做处理
GET    /api/v1/graph/endpoint                           Endpoint List                                  是
GET    /api/v1/graph/endpoint_counter                   Get Counter of Endpoint                        是
PUT    /api/v1/expression                               Update Expression                              是
GET    /api/v1/expression                               Expression List                                是
GET    /api/v1/expression/#{expression_id}              Get Expression Info by id                      是
DELETE /api/v1/expression/#{expression_id}              Delete Expression                              是
POST   /api/v1/expression                               Create Expression                              是
PUT    /api/v1/dashboard/screen/:screen_id              Update a DashboardScreen                       是
GET    /api/v1/dashboard/screens/pid/:screen_pid        Gets DashboardScreens by pid                   是
GET    /api/v1/dashboard/screens                        Gets all DashboardScreens                      是
GET    /api/v1/dashboard/screen/:screen_id              Get a DashboardScreen by id                    是
DELETE /api/v1/dashboard/screen/:screen_id              Delete a DashboardScreen                       是
POST   /api/v1/dashboard/screen                         Create a DashboardScreen                       是
GET    /api/v1/dashboard/graphs/screen/:screen_id       Gets graphs by screen id                       是
PUT    /api/v1/dashboard/graph/:id                      Update a DashboardGraph                        是
GET    /api/v1/dashboard/tmpgraph/:id                   Get a tmpgraph by id                           是
GET    /api/v1/dashboard/graph/:id                      Get DashboardGraph info by id                  是                
DELETE /api/v1/dashboard/graph/:id                      Delete a DashboardGraph                        是
POST   /api/v1/dashboard/tmpgraph                       Create a tmpgraph                              是 
POST   /api/v1/dashboard/graph                          Create Graph                                   是            
POST   /api/v1/alarm/events                             Create Events                                  是
GET    /api/v1/alarm/event_note                         Get Event Note by id or time range             是
POST   /api/v1/alarm/event_note                         Create Event Note                              是
POST   /api/v1/alarm/eventcases                         EventCases List                                是
GET    /api/v1/alarm/eventcases                         Get EventCases by id                           是
GET    /api/v1/aggregator                               Get Aggreator Info by id                       是
PUT    /api/v1/aggregator                               Update Aggreator                               是
GET    /api/v1/hostgroup/#{hostgroup_id}/aggregators    Get Aggreator List of HostGroup                是
DELETE /api/v1/aggregator/16                            Delete Aggreator                               是
POST    /api/v1/aggregator                              Create Aggreator to a HostGroup                是
DELETE /api/v1/admin/delete_user                        Delete User                                    是
PUT    /api/v1/admin/change_user_passwd                 Change User's Password                         是
PUT    /api/v1/admin/change_user_role                   Change User's role                             是
GET    /api/v1/user/auth_session                        Auth Session                                   是