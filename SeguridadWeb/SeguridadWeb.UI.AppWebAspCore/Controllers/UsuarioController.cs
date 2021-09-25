using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

/********************************/
using SeguridadWeb.EntidadesDeNegocio;
using SeguridadWeb.LogicaDeNegocio;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
/****************Using para consumir API************************/
using System.Net.Http;
using System.Text.Json;
using System.Net.Http.Json;

namespace SeguridadWeb.UI.AppWebAspCore.Controllers
{
    //[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class UsuarioController : Controller
    {
        UsuarioBL usuarioBL = new UsuarioBL();
        RolBL rolBL = new RolBL();

        private readonly HttpClient _httpClient;
        public UsuarioController(HttpClient client)
        {
            _httpClient = client;
        }


        // GET: UsuarioController
        public async Task<IActionResult> Index(Usuario pUsuario = null)
        {
            if (pUsuario == null)
                pUsuario = new Usuario();
            if (pUsuario.Top_Aux == 0)
                pUsuario.Top_Aux = 10;
            else if (pUsuario.Top_Aux == -1)
                pUsuario.Top_Aux = 0;

            var usuarios = new List<Usuario>();
            var roles = new List<Rol>();

            var response = await _httpClient.PostAsJsonAsync("Usuario/Buscar", pUsuario);
            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                usuarios = JsonSerializer.Deserialize<List<Usuario>>(responseBody,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            var responseRol = await _httpClient.GetAsync("Rol");
            if (responseRol.IsSuccessStatusCode)
            {
                var responseBodyRol = await responseRol.Content.ReadAsStringAsync();
                roles = JsonSerializer.Deserialize<List<Rol>>(responseBodyRol,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            //var taskBuscar = usuarioBL.BuscarIncluirRolesAsync(pUsuario);
            //var taskObtenerTodosRoles = rolBL.ObtenerTodosAsync();
            //var usuarios = await taskBuscar;
            ViewBag.Top = pUsuario.Top_Aux;
            ViewBag.Roles = roles;
            return View(usuarios);
        }


        // GET: UsuarioController/Details/5
        public async Task<IActionResult> Details(int id)
        {
            Usuario usuario = new Usuario();
            var response = await _httpClient.GetAsync("Usuario/" + id);
            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                usuario = JsonSerializer.Deserialize<Usuario>(responseBody,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            Rol rol = new Rol();
            var idRol = usuario.IdRol;
            var responseRol = await _httpClient.GetAsync("Rol/" + idRol);
            if (responseRol.IsSuccessStatusCode)
            {
                var responseBodyRol = await responseRol.Content.ReadAsStringAsync();
                rol = JsonSerializer.Deserialize<Rol>(responseBodyRol,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            usuario.Rol = rol;
            return View(usuario);
        }


        // GET: UsuarioController/Create
        public async Task<IActionResult> Create()
        {
            var roles = new List<Rol>();
            var response = await _httpClient.GetAsync("Rol");
            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                roles = JsonSerializer.Deserialize<List<Rol>>(responseBody,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            ViewBag.Roles = roles;
            ViewBag.Error = "";
            return View();
        }


        // POST: UsuarioController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Usuario pUsuario)
        {
            try
            {
                var response = await _httpClient.PostAsJsonAsync("Usuario", pUsuario);
                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    ViewBag.Error = "Sucedio un error al consumir la WEP API";
                    return View(pUsuario);
                }
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                //ViewBag.Roles = await rolBL.ObtenerTodosAsync();
                return View(pUsuario);
            }
        }


        // GET: UsuarioController/Edit/5
        public async Task<IActionResult> Edit(Usuario pUsuario)
        {
            var usuario = new Usuario();
            
            var response = await _httpClient.GetAsync("Usuario/" + pUsuario.Id);
            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                usuario = JsonSerializer.Deserialize<Usuario>(responseBody,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); 
            }

            var roles = new List<Rol>();
            //Para cargar todos los roles.
            var responseRol = await _httpClient.GetAsync("Rol");
            if (responseRol.IsSuccessStatusCode)
            {
                var responseBodyRol = await responseRol.Content.ReadAsStringAsync();
                roles = JsonSerializer.Deserialize<List<Rol>>(responseBodyRol,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            ViewBag.Roles = roles;
            ViewBag.Error = "";
            return View(usuario);
        }


        // POST: UsuarioController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Usuario pUsuario)
        {
            try
            {
                var response = await _httpClient.PutAsJsonAsync("Usuario/" + id, pUsuario);
                if (response.IsSuccessStatusCode)
                {
                     
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    var roles = new List<Rol>();
                    //Para cargar todos los roles.
                    var responseRol = await _httpClient.GetAsync("Rol");
                    if (response.IsSuccessStatusCode)
                    {
                        var responseBodyRol = await responseRol.Content.ReadAsStringAsync();
                        roles = JsonSerializer.Deserialize<List<Rol>>(responseBodyRol,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    }

                    ViewBag.Roles = roles;
                    ViewBag.Error = "Sucedio un error al consumir la WEP API";
                    return View(pUsuario);
                }
                // int result = await rolBL.ModificarAsync(pRol);

            }
            catch (Exception ex)
            {
                var roles = new List<Rol>();
                //Para cargar todos los roles.
                var responseRol = await _httpClient.GetAsync("Rol");
                if (responseRol.IsSuccessStatusCode)
                {
                    var responseBodyRol = await responseRol.Content.ReadAsStringAsync();
                    roles = JsonSerializer.Deserialize<List<Rol>>(responseBodyRol,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }

                ViewBag.Roles = roles;
                ViewBag.Error = ex.Message;
                return View(pUsuario);
            }
        }


        // GET: UsuarioController/Delete/5
        public async Task<IActionResult> Delete(Usuario pUsuario)
        {
            Usuario usuario = new Usuario();
            var response = await _httpClient.GetAsync("Usuario/" + pUsuario.Id);
            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                usuario = JsonSerializer.Deserialize<Usuario>(responseBody,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            Rol rol = new Rol();
            var idRol = usuario.IdRol;
            var responseRol = await _httpClient.GetAsync("Rol/" + idRol);
            if (responseRol.IsSuccessStatusCode)
            {
                var responseBodyRol = await responseRol.Content.ReadAsStringAsync();
                rol = JsonSerializer.Deserialize<Rol>(responseBodyRol,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            usuario.Rol = rol;
            return View(usuario);
        }


        // POST: UsuarioController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(int id, Usuario pUsuario)
        {
            try
            {
                var response = await _httpClient.DeleteAsync("Usuario/" + id);
                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    ViewBag.Error = "Sucedio un error al consumir la WEP API";
                    return View(pUsuario);
                }
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                //var usuario = await usuarioBL.ObtenerPorIdAsync(pUsuario);
                //if (usuario == null)
                //    usuario = new Usuario();
                //if (usuario.Id > 0)
                //    usuario.Rol = await rolBL.ObtenerPorIdAsync(new Rol { Id = usuario.IdRol });
                return View(pUsuario);
            }
        }

        // GET: UsuarioController/Create
        [AllowAnonymous]
        public async Task<IActionResult> Login(string ReturnUrl = null)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            ViewBag.Url = ReturnUrl;
            ViewBag.Error = "";
            return View();
        }

        // POST: UsuarioController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Login(Usuario pUsuario, string pReturnUrl = null)
        {
            try
            {
                var usuario = await usuarioBL.LoginAsync(pUsuario);
                if (usuario != null && usuario.Id > 0 && pUsuario.Login == usuario.Login)
                {
                    usuario.Rol = await rolBL.ObtenerPorIdAsync(new Rol { Id = usuario.IdRol });
                    var claims = new[] { new Claim(ClaimTypes.Name, usuario.Login), new Claim(ClaimTypes.Role, usuario.Rol.Nombre) };
                    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
                }
                else
                    throw new Exception("Credenciales incorrectas");
                if (!string.IsNullOrWhiteSpace(pReturnUrl))
                    return Redirect(pReturnUrl);
                else
                    return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                ViewBag.Url = pReturnUrl;
                ViewBag.Error = ex.Message;
                return View(new Usuario { Login = pUsuario.Login });
            }
        }
        [AllowAnonymous]
        public async Task<IActionResult> CerrarSesion(string ReturnUrl = null)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Usuario");
        }
        // GET: UsuarioController/Create
        public async Task<IActionResult> CambiarPassword()
        {

            var usuarios = await usuarioBL.BuscarAsync(new Usuario { Login = User.Identity.Name, Top_Aux = 1 });
            var usuarioActual = usuarios.FirstOrDefault();
            ViewBag.Error = "";
            return View(usuarioActual);
        }

        // POST: UsuarioController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CambiarPassword(Usuario pUsuario, string pPasswordAnt)
        {
            try
            {
                int result = await usuarioBL.CambiarPasswordAsync(pUsuario, pPasswordAnt);
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return RedirectToAction("Login", "Usuario");
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                var usuarios = await usuarioBL.BuscarAsync(new Usuario { Login = User.Identity.Name, Top_Aux = 1 });
                var usuarioActual = usuarios.FirstOrDefault();
                return View(usuarioActual);
            }
        }
    }
}
