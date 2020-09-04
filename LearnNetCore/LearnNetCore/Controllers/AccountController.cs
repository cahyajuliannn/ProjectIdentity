using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LearnNetCore.Context;
using LearnNetCore.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LearnNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly MyContext _context;
        private readonly UserManager<User> _userManager;

        public AccountController(MyContext myContext, UserManager<User> userManager)
        {
            _context = myContext;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("login")]
        public IActionResult Login(UserViewModel userVM)
        {
            if (ModelState.IsValid)
            {
                var pwd = userVM.Password;
                var masuk = _context.UserRoles.Include("Role").Include("User").SingleOrDefault(m => m.User.Email == userVM.Email);
                if (masuk == null)
                {
                    return BadRequest("Please use the existing email or register first");
                }
                else if (!BCrypt.Net.BCrypt.Verify(userVM.Password, masuk.User.PasswordHash))
                {
                    return BadRequest("Incorret password");
                }
                else if (pwd == null || pwd.Equals(""))
                {
                    return BadRequest("Please enter the password");
                }
                else
                {
                    var user = new UserViewModel();
                    user.Id = masuk.User.Id;
                    user.Username = masuk.User.UserName;
                    user.Email = masuk.User.Email;
                    user.Phone = masuk.User.PhoneNumber;
                    user.RoleName = masuk.Role.Name;
                    return StatusCode(200, user);
                }
            }
            return BadRequest(500);
        }

        [HttpPost]
        [Route("register")]
        public IActionResult Register(RegisterViewModel registerVM)
        {
                var pwHashed = BCrypt.Net.BCrypt.HashPassword(registerVM.Password, 12);
                var user = new User
                {
                    Email = registerVM.Email,
                    PasswordHash = pwHashed,
                    UserName = registerVM.Username,
                    EmailConfirmed = false,
                    PhoneNumber = registerVM.Phone,
                    PhoneNumberConfirmed = false,
                    TwoFactorEnabled = false,
                    LockoutEnabled = false,
                    AccessFailedCount = 0
                };
                _context.Users.AddAsync(user);
                var role = new UserRole
                {
                    UserId = user.Id,
                    RoleId = "2"
                };
                _context.UserRoles.AddAsync(role);
                _context.SaveChanges();
                return Ok("Registered successfully");

        }
        // GET api/values
        [HttpGet]
        public async Task<List<UserViewModel>> GetAll()
        {
            List<UserViewModel> list = new List<UserViewModel>();
            var user = new UserViewModel();
            var getUserRole = await _context.UserRoles.Include("User").Include("Role").ToListAsync();
            if (getUserRole.Count == 0)
            {
                return null;
            }
            foreach (var item in getUserRole)
            {
                user.Id = item.User.Id;
                user.Username = item.User.UserName;
                user.Email = item.User.Email;
                user.Password = item.User.PasswordHash;
                user.Phone = item.User.PhoneNumber;
                user.RoleName = item.Role.Name;
                list.Add(user);
            }
            return list;
        }
        [HttpGet("{id}")]
        public UserViewModel GetID(string id)
        {

            var getData = _context.UserRoles.Include("User").Include("Role").SingleOrDefault(x => x.UserId == id);
            if (getData == null || getData.Role == null || getData.User == null)
            {
                return null;
            }
            var user = new UserViewModel()
            {
                Id = getData.User.Id,
                Username = getData.User.UserName,
                Email = getData.User.Email,
                Password = getData.User.PasswordHash,
                Phone = getData.User.PhoneNumber,
                RoleID = getData.Role.Id,
                RoleName = getData.Role.Name
            };
            return user;
        }
        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            var getId = _context.Users.Find(id);
            _context.Users.Remove(getId);
            _context.SaveChanges();
            return Ok("Deleted succesfully");
        }
        [HttpPost]
        public IActionResult Create(UserViewModel userVM)
        {
            if (ModelState.IsValid)
            {
                var pwHashed = BCrypt.Net.BCrypt.HashPassword(userVM.Password, 12);
                var user = new User
                {
                    UserName = userVM.Username,
                    Email = userVM.Email,
                    PasswordHash = pwHashed,
                    PhoneNumber = userVM.Phone,
                    EmailConfirmed = false,
                    PhoneNumberConfirmed = false,
                    TwoFactorEnabled = false,
                    LockoutEnabled = false,
                    AccessFailedCount = 0
                };
                _context.Users.Add(user);
                var uRole = new UserRole
                {
                    UserId = user.Id,
                    RoleId = "2"
                };
                _context.UserRoles.Add(uRole);
                _context.SaveChanges();
                return Ok("Successfully Created");
            }
            return BadRequest("Not Successfully");
        }
    }
}
