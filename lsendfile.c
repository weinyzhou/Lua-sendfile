#include <lua.h>//Lua 5.1.5
#include <lauxlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>  
 
#include "time.h"  
#include "unistd.h"

#include "ngx_http_lua_common.h"
#include "ngx_http_lua_util.h"


static int ngx_http_lua_sendfile(lua_State *L)
{
    u_char                    *last, *location;
    size_t                     root, len;
    ngx_http_request_t        *r;
    ngx_str_t                  path;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
	int                        offset;
	int                        bytes;
	char                      *filename;
	int                        nargs;

    lua_pushlightuserdata(L, &ngx_http_lua_request_key);
    lua_rawget(L, LUA_GLOBALSINDEX);
    r = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (r == NULL) 
    {
        luaL_error(L, "no request object found");
	return 1;
    }

 
    nargs = lua_gettop(L);

	filename = (char *) lua_tolstring(L, 1, &len);
	offset   = lua_tonumber(L, 2);
	bytes    = lua_tonumber(L, 3);

    log = r->connection->log;

    path.len = ngx_strlen(filename);

    path.data = ngx_pnalloc(r->pool, path.len + 1);
    if (path.data == NULL) {
        return 0;
    }

    (void) ngx_cpystrn(path.data, (u_char *) filename, path.len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "ngx send lua filename: \"%s\"", filename);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) 
    {
        return 0;//NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) != NGX_OK)
    {
        switch (of.err) 
	{

        case 0:
            return 0;//NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) 
	{
            ngx_log_error(level, log, of.err, "%s \"%s\" failed", of.failed, path.data);
        }

        return 0;//rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (offset < 0) {
        offset = 0;
    }

    if (bytes <= 0) {
        bytes = of.size - offset;
    }


#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) 
    {
        ngx_log_error(NGX_LOG_CRIT, log, 0, "\"%s\" is not a regular file", path.data);

        return 0;//NGX_HTTP_NOT_FOUND;
    }

#endif

    if (r->method & NGX_HTTP_POST) 
    {
        return 0;//NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) 
    {
        return 0;//rc;
    }

    log->action = "sending response to client";

    len = (offset + bytes) >= of.size ? of.size : (offset + bytes);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len - offset;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_content_type(r) != NGX_OK) 
    {
        return 0;//NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) 
    {
         ngx_http_send_header(r);
		 return 0;//
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) 
    {
        return 0;//NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) 
    {
        return 0;//NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) 
    {
        return 0;//rc;
    }

    b->file_pos = offset;
    b->file_last = (offset + bytes) >= of.size ? of.size : (offset + bytes);

    b->in_file = 1;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    ngx_http_output_filter(r, &out);
    return 0;//
}




static const struct luaL_Reg sendfile_lib[] = {
	{ "call", ngx_http_lua_sendfile },
	{ NULL, NULL }
};



#define LUA_MACLIBNAME "sendfile"

LUALIB_API int luaopen_sendfile(lua_State *L)
{
	luaL_register(L, LUA_MACLIBNAME, sendfile_lib);

	return 1;
}
