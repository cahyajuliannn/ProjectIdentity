using Microsoft.EntityFrameworkCore.Migrations;

namespace LearnNetCore.Migrations
{
    public partial class addNew : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_tb_m_user_tb_role_RoleId",
                table: "tb_m_user");

            migrationBuilder.DropForeignKey(
                name: "FK_tb_m_userrole_tb_role_RoleId",
                table: "tb_m_userrole");

            migrationBuilder.DropPrimaryKey(
                name: "PK_tb_m_userrole",
                table: "tb_m_userrole");

            migrationBuilder.DropIndex(
                name: "IX_tb_m_user_RoleId",
                table: "tb_m_user");

            migrationBuilder.DropColumn(
                name: "RoleId",
                table: "tb_m_user");

            migrationBuilder.AlterColumn<string>(
                name: "RoleId",
                table: "tb_m_userrole",
                nullable: false,
                oldClrType: typeof(string),
                oldNullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_tb_m_userrole",
                table: "tb_m_userrole",
                columns: new[] { "UserId", "RoleId" });

            migrationBuilder.AddForeignKey(
                name: "FK_tb_m_userrole_tb_role_RoleId",
                table: "tb_m_userrole",
                column: "RoleId",
                principalTable: "tb_role",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_tb_m_userrole_tb_role_RoleId",
                table: "tb_m_userrole");

            migrationBuilder.DropPrimaryKey(
                name: "PK_tb_m_userrole",
                table: "tb_m_userrole");

            migrationBuilder.AlterColumn<string>(
                name: "RoleId",
                table: "tb_m_userrole",
                nullable: true,
                oldClrType: typeof(string));

            migrationBuilder.AddColumn<string>(
                name: "RoleId",
                table: "tb_m_user",
                nullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_tb_m_userrole",
                table: "tb_m_userrole",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_tb_m_user_RoleId",
                table: "tb_m_user",
                column: "RoleId");

            migrationBuilder.AddForeignKey(
                name: "FK_tb_m_user_tb_role_RoleId",
                table: "tb_m_user",
                column: "RoleId",
                principalTable: "tb_role",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_tb_m_userrole_tb_role_RoleId",
                table: "tb_m_userrole",
                column: "RoleId",
                principalTable: "tb_role",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }
    }
}
