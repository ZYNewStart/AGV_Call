using System;
using AGV_CALL;
using AGV_CALL_Global;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows;
using System.Windows.Input;
using System.Data.SqlClient;


namespace AGV_CALL
{
    /// <summary>
    /// Login.xaml 的交互逻辑
    /// </summary>
   
    public partial class Login : Window
    {

        #region 构造函数
        public Login()
        {
            InitializeComponent();
            this.UserNametextBox.Text = Properties.Settings.Default.UserName;
            this.passwordBox.Focus();
        }
        #endregion

        #region 退出系统
        private void Exitbutton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
        #endregion

        #region 设置快捷键
        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                this.Loginbutton_Click(sender, null);
            }
            if (e.Key == Key.Escape)
            {
                Application.Current.Shutdown();
            }
        }
        #endregion

        #region 登录系统
        private void Loginbutton_Click(object sender, RoutedEventArgs e)
        {
            string UserName = this.UserNametextBox.Text.ToLower().Trim();
            string PassWord = this.passwordBox.Password.ToLower().Trim();
            DAL.ZSql sql = new DAL.ZSql();
            int i = sql.Open("select * from T_UserInfo where UserName=@username and Pwd=@password", new SqlParameter[] { new SqlParameter("username", UserName), new SqlParameter("password", PassWord) });
            if (i < 0)
            {
                sql.Close();
                return;
            }
            if (sql.Rows.Count > 0)
            {
                if (sql.Rows[0]["IsManager"].ToString() == "True")
                {
                    GlobalPara.IsManager = true;
                }
                else
                {
                    GlobalPara.IsManager = false;
                }
                GlobalPara.strName = UserName;
                GlobalPara.userid = sql.Rows[0]["ID"].ToString();
                sql.Close();
                MainWindow mn = new MainWindow();
                mn.Show();
                this.Close();
            }
            else
            {
                MessageBox.Show("用户名或密码错误，请检查", "警告");
                this.UserNametextBox.Clear();
                this.passwordBox.Clear();
                this.UserNametextBox.Focus();
            }
            sql.Close();
        }
        #endregion
        
        #region 窗体加载与退出
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            //if (CheckSoftKey() != 0)
            //{
            //    MessageBox.Show("未能找到指定的加密锁", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            //    Application.Current.Shutdown();
            //    return;
            //}
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Properties.Settings.Default.UserName = this.UserNametextBox.Text.ToLower().Trim();
            Properties.Settings.Default.Save();//使用Save方法保存更改
        }
        #endregion

    }
}

