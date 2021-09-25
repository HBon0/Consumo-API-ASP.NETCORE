using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
// ********************************
using Microsoft.EntityFrameworkCore;
using SeguridadWeb.EntidadesDeNegocio;

namespace SeguridadWeb.AccesoADatos
{
    public class BDContexto : DbContext
    {
        public DbSet<Rol> Rol { get; set; }
        public DbSet<Usuario> Usuario { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            //optionsBuilder.UseSqlServer(@"Data Source=LAPTOP-I2KG7UCJ\SQLEXPRESS;Initial Catalog=SeguridadWebdb;Integrated Security=True");
            //String de Hector.
            optionsBuilder.UseSqlServer(@"Data Source=DESKTOP-52V3E4O;Initial Catalog=SeguridadWebdb;Integrated Security=True");
        }
    }
}
