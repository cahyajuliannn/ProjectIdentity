using LearnNetCore.Context;
using LearnNetCore.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnNetCore.Repositories
{
    public class UserRepository : IUserRepository
    {
        MyContext db;
        public UserRepository(MyContext _db)
        {
            db = _db;
        }

        public async Task<List<UserViewModel>> GetUsers()
        {
            //if (db != null)
            //{
            List<UserViewModel> list = new List<UserViewModel>();
            foreach (var item in db.Users)
            {
                UserViewModel user = new UserViewModel()
                {
                    Id = item.Id,
                    Username = item.UserName,
                    Email = item.Email,
                    Password = item.PasswordHash,
                    Phone = item.PhoneNumber
                };
                list.Add(user);
            }
            return list;
            //}

            //return null;
        }

        //public async Task<UserViewModel> GetUser(string Id)
        //{

        //        return await (from p in db.Users
        //                      where p.Id == Id
        //                      select new UserViewModel
        //                      {
        //                          Id = p.Id,
        //                          Email = p.Email,
        //                          Username = p.UserName
        //                      }).FirstOrDefaultAsync();
        //}

        public async Task<string> AddUser(UserViewModel userVM)
        {
            if (db != null)
            {
                var user = new User();
                user.Id = userVM.Id;
                user.UserName = userVM.Username;
                user.Email = userVM.Email;
                user.EmailConfirmed = false;
                user.PasswordHash = userVM.Password;
                user.PhoneNumber = userVM.Phone;
                user.PhoneNumberConfirmed = false;
                user.TwoFactorEnabled = false;
                user.LockoutEnabled = false;
                user.AccessFailedCount = 0;
                //var data = await db.Users.AddAsync(user);
                //return Ok("Successfully Created");
                await db.Users.AddAsync(user);
                await db.SaveChangesAsync();

                return user.Id;
            }

            return null;
        }

        //public async Task<string> DeleteUsers(string id)
        //{
        //    var post = await db.Users.FirstOrDefaultAsync(x => x.Id == id);
        //    db.Users.Remove(post);
        //    await db.SaveChangesAsync();

        //}


        //public async Task UpdateUser(UserViewModel user)
        //{
        //    if (db != null)
        //    {
        //        //Delete that post
        //        db.Users.Update(user);

        //        //Commit the transaction
        //        await db.SaveChangesAsync();
        //    }
        //}
    }
}
