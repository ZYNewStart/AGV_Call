using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Configuration;
using AGV_CALL_Global;

namespace AGV_CALL
{
    /// <summary>
    /// COMSetting.xaml 的交互逻辑
    /// </summary>
    public partial class CallCOMSetting : Window
    {
        /// <summary>
        /// 串口设置页面构造函数
        /// </summary>
        public CallCOMSetting()
        {
            InitializeComponent();
            cbCallcomname.Text = GlobalPara.GCallcomname;
            Configuration cfa = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            cbCallcombaudrate.Text = cfa.AppSettings.Settings["CallCOMBaudrate"].Value;
            cbCallcomdatabits.Text = cfa.AppSettings.Settings["CallCOMDataBits"].Value;
            cbCallcomstopbits.Text = cfa.AppSettings.Settings["CallCOMStopBits"].Value;
            cbCallcomparity.Text = cfa.AppSettings.Settings["CallCOMParity"].Value;
        }

        /// <summary>
        /// 确认修改消息响应
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnCall_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                bool resetflag = false;
                Configuration cfa = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                if (!cfa.AppSettings.Settings["CallCOMBaudrate"].Value.Equals(cbCallcombaudrate.Text.Trim()))
                {
                    cfa.AppSettings.Settings["CallCOMBaudrate"].Value = cbCallcombaudrate.Text.Trim();
                    resetflag = true;
                }
                if (!cfa.AppSettings.Settings["CallCOMDataBits"].Value.Equals(cbCallcomdatabits.Text.Trim()))
                {
                    cfa.AppSettings.Settings["CallCOMDataBits"].Value = cbCallcomdatabits.Text.Trim();
                    resetflag = true;
                }
                if (!cfa.AppSettings.Settings["CallCOMStopBits"].Value.Equals(cbCallcomstopbits.Text.Trim()))
                {
                    cfa.AppSettings.Settings["CallCOMStopBits"].Value = cbCallcomstopbits.Text.Trim();
                    resetflag = true;
                }
                if (!cfa.AppSettings.Settings["CallCOMParity"].Value.Equals(cbCallcomparity.Text.Trim()))
                {
                    cfa.AppSettings.Settings["CallCOMParity"].Value = cbCallcomparity.Text.Trim();
                    resetflag = true;
                }
                if (resetflag)
                {
                    MessageBox.Show("修改成功！重启软件生效。");
                    this.Close();
                }
                else
                {
                    if (!GlobalPara.GCallcomname.Equals(cbCallcomname.Text.Trim()))
                    {
                        GlobalPara.GCallcomname = cbCallcomname.Text.Trim();
                        cfa.AppSettings.Settings["CallCOMName"].Value = cbCallcomname.Text.Trim();
                        MessageBox.Show("修改成功！");
                        this.Close();
                    }
                }
                cfa.Save(ConfigurationSaveMode.Minimal, false);
            }
            catch (System.Exception ex)
            {
                MessageBox.Show("修改失败！");
            }
        }


        #region 退出系统
        /// <summary>
        /// 退出系统
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnExit_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
        #endregion

    }
}
