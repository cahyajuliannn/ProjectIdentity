using LearnNetCore.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnNetCore.Repositories
{
    interface IUserRepository
    {
        Task<List<UserViewModel>> GetUsers();

        //Task<UserViewModel> GetUser(string Id);

        Task<string> AddUser(UserViewModel user);

        //Task<string> DeletePost(string Id);

        //Task UpdateUser(UserViewModel user);
    }
}
