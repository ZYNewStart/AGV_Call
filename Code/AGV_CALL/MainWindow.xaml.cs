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
using System.Windows.Navigation;
using System.Windows.Shapes;
using DAL;
using COM;
using System.Configuration;
using System.IO.Ports;
using System.Threading;
using System.Data;
using AGV_CALL_Global;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using AGV_CALL_Info;
using System.ComponentModel;

namespace AGV_CALL
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        #region 类变量
        //帧校验结果
        public const byte VERIFY_NOERROR = 0;
        public const byte VERIFY_HEADERROR = 1;
        public const byte VERIFY_ENDERROR = 2;
        public const byte VERIFY_FUNERROR = 3;
        public const byte VERIFY_BCCERROR = 4;

        /// <summary>
        /// 提供数据库操作
        /// </summary>
        private DAL.ZSql callSql = new DAL.ZSql();

        /// <summary>
        /// 串口操作
        /// </summary>
        public COM.SerialPortWrapper SPComCall;

        /// <summary>
        /// 动态数据集，更新表格数据
        /// </summary>
        ObservableCollection<AGV_CALLMember> memberData = new ObservableCollection<AGV_CALLMember>();

        /// <summary>
        /// 动态数据库添加数据操作委托
        /// </summary>
        /// <param name="si"></param>
        private delegate void AddCallMemberEvent(AGV_CALLMember si);

        /// <summary>
        /// 动态数据库删除数据操作委托
        /// </summary>
        /// <param name="si"></param>
        private delegate void DeleteCallMemberEvent(AGV_CALLMember si);

        /// <summary>
        /// 叫料系统接收信息缓冲区
        /// </summary>
        byte[] buf_callctl = { 0x10, 0x00, 0x00, 0x00, 0x00, 0x03 };//为什么线路要从0x30开始？为什么采用CRC效验，不采用异或效验？

        /// <summary>
        /// 叫料系统发送信息缓冲区
        /// </summary>
        byte[] buf_callret = { 0x10, 0x00, 0x00, 0x00, 0x00, 0x03 };

        #endregion

        #region 事件委托触发更新

        private void LaunchTimer()
        {
            DispatcherTimer innerTimer = new DispatcherTimer(TimeSpan.FromSeconds(1.0),
                    DispatcherPriority.Loaded, new EventHandler(this.TimerTick), this.Dispatcher);
            innerTimer.Start();
        }

        private void TimerTick(object sender, EventArgs e)
        {
            lblTime.Content = DateTime.Now.ToString();
        }

        /// <summary>
        /// 串口类SerialPortWrapper的数据接收触发委托函数
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SPComCall_OnDataReceived(object sender, SerialDataReceivedEventArgs e)
        {
            Thread.Sleep(10);
            Array.Clear(buf_callctl, 0, buf_callctl.Length);
            SPComCall.Read(buf_callctl, 0, buf_callctl.Length);
            ReceivedDataHandle(buf_callctl);
        }

        /// <summary>
        /// 数据接收处理,添加、删除记录
        /// </summary>
        /// <param name="buf"></param>
        private void ReceivedDataHandle(byte[] buf)
        {
            byte[] databuffer = buf;
            if (CallDataCheck(databuffer, databuffer.Length - 2) == VERIFY_NOERROR)
            {
                if (databuffer[1] == 0x41)//叫料
                {
                    if (Add(databuffer[2], databuffer[3]))
                    {
                        buf_callret[0] = 0x10;
                        buf_callret[1] = 0x43;
                        buf_callret[2] = buf[2];
                        buf_callret[3] = buf[3];
                        buf_callret[4] = DrvWlConGetBCC(buf_callret, buf_callctl.Length - 2);
                        buf_callret[5] = 0x03;
                        SPComCall.Write(buf_callret, 0, buf_callret.Length);
                    }
                }
                else if (databuffer[1] == 0x42)//取消叫料
                {
                    if (Delete(databuffer[2], databuffer[3]))
                    {
                        buf_callret[0] = 0x10;
                        buf_callret[1] = 0x45;
                        buf_callret[2] = buf[2];
                        buf_callret[3] = buf[3];
                        buf_callret[4] = DrvWlConGetBCC(buf_callret, buf_callctl.Length - 2);
                        buf_callret[5] = 0x03;
                        SPComCall.Write(buf_callret, 0, buf_callret.Length);
                    }
                }
            }
        }

        /// <summary>
        /// 跑马灯更新
        /// </summary>
        private void UpdateInfo()
        {
            lbInfo.Content = "";
            if (memberData.Count > 0)
            {
                for (int i = 0; i < memberData.Count; i++)
                {
                    lbInfo.Content += "工位：" + memberData[i].iStationNum.ToString() + "(" + memberData[i].iMaterialNum.ToString() + ")" + " " + memberData[i].sMaterialName + "        ";
                }
            }
            else
            {
                lbInfo.Content = "无缺料信息...";
            }
            //动态变化跑马灯的高度
            //lbInfo.Height = memberData.Count * lbInfo.FontSize * 2;
        }

        /// <summary>
        /// 历史记录更新
        /// </summary>
        /// <param name="strInput">添加字符串</param>
        /// <param name="fontColor">字符串字体颜色</param>
        public void RichTextBoxUpdate(string strInput, Color fontColor)
        {
            TextPointer tpend = rtbHistory.Document.ContentEnd;
            rtbHistory.AppendText(strInput);
            //TextPointer tpstart = rtbHistory.Document.ContentEnd; 
            int p2 = strInput.Length + 4;
            TextPointer tpstart = tpend.GetPositionAtOffset(-1 * p2);
            TextRange range = rtbHistory.Selection;
            range.Select(tpstart, tpend);
            range.ApplyPropertyValue(TextElement.ForegroundProperty, new SolidColorBrush(fontColor));
            //rtbHistory.SelectionBrush = fontColor;
        }

        /// <summary>
        /// 添加成员
        /// </summary>
        /// <param name="si">成员数据</param>
        private void AddCallMember(AGV_CALLMember si)
        {
            memberData.Add(si);
            RichTextBoxUpdate(si.dtTime.ToString() + ":工位" + si.iStationNum.ToString() + "(" + si.iMaterialNum.ToString() + ") 缺" + si.sMaterialName + "\r\n", Colors.Red);
            UpdateInfo();
        }

        /// <summary>
        /// 删除成员
        /// </summary>
        /// <param name="si">成员数据</param>
        private void DeleteCallMember(AGV_CALLMember si)
        {
            memberData.Remove(si);
            RichTextBoxUpdate(si.dtTime.ToString() + ":工位" + si.iStationNum.ToString() + "(" + si.iMaterialNum.ToString() + ")" + "取消叫料成功" + "\r\n", Colors.Green);
            UpdateInfo();
        }

        /// <summary>
        /// 添加
        /// </summary>
        /// <param name="route">路线</param>
        public bool Add(int stationnum, int materialnum)
        {
            bool flag = false;
            if (stationnum > 0 && materialnum > 0)
            {
                bool bFind = memberData.Any<AGV_CALLMember>(p => p.iStationNum == stationnum && p.iMaterialNum == materialnum);
                if (!bFind)
                {
                    AGV_CALLMember DisMember = new AGV_CALLMember();
                    DisMember.iNO = memberData.Count + 1;
                    DisMember.dtTime = DateTime.Now;
                    DisMember.iStationNum = stationnum;
                    DisMember.iMaterialNum = materialnum;
                    callSql.Open("Select * from T_CallSetting where StationNum=" + stationnum.ToString() + " and MaterialNum=" + materialnum);
                    if (callSql.rowcount > 0)
                    {
                        DisMember.sMaterialName = callSql.Rows[0]["MaterialName"].ToString();
                        DisMember.iLineNum = Convert.ToInt32(callSql.Rows[0]["LineNum"]);
                        flag = true;
                    }
                    callSql.Close();
                    /*********************************
                     http://blog.csdn.net/luminji/article/details/5353644
                    典型应用场景：WPF页面程序中，ListView的ItemsSource是一个ObservableCollection<StudentInfo>；
                    操作：另起一个线程，为ListView动态更新数据，也就是给ObservableCollection<StudentInfo>添加记录。
                    这类操作，就是跨线程访问线程安全的数据，如果不使用Dispatcher，就会导致出错“该类型的CollectionView
                    不支持从调度程序线程以外的线程对其SourceCollection”。
                    **********************************/
                    Dispatcher.Invoke(new AddCallMemberEvent(this.AddCallMember), DisMember);
                    //AddCallMember(DisMember);
                }
            }
            return flag;
        }

        /// <summary>
        /// 删除
        /// </summary>
        public bool Delete(int stationnum, int materialnum)
        {
            bool flag = false;
            if (stationnum > 0 && materialnum > 0)
            {
                bool bFind = memberData.Any<AGV_CALLMember>(p => p.iStationNum == stationnum && p.iMaterialNum == materialnum);
                if (bFind)
                {
                    IEnumerable<AGV_CALLMember> deletemember1 = memberData.Where<AGV_CALLMember>(p => p.iStationNum == stationnum && p.iMaterialNum == materialnum);
                    AGV_CALLMember member1 = deletemember1.First<AGV_CALLMember>();
                    Dispatcher.Invoke(new DeleteCallMemberEvent(this.DeleteCallMember), member1);
                    //DeleteCallMember(member1);
                    flag = true;
                }
            }
            return flag;
        }
        #endregion

        #region 数据效验

        /// <summary>
        /// 数据格式效验
        ///  0x10 功能码 工位号 异或效验 0x03
        ///  起始位 功能码（0x41 叫料 0x42 取消叫料 0x43 叫料成功 0x44 设置工位号成功 0x45 取消叫料成功）
        /// </summary>
        /// <param name="buf">接收帧数据</param>
        /// <returns>返回效验结果</returns>
        public static int CallDataCheck(byte[] buf, int length)
        {
            if (buf[0] != 0x10)
            {
                return VERIFY_HEADERROR;//头错误
            }
            else if ((buf[buf.Length - 1]) != 0x03)
            {
                return VERIFY_ENDERROR;//尾错误
            }
            else if (buf[1] != 0x41 && buf[1] != 0x42 && buf[1] != 0x43 && buf[1] != 0x44 && buf[1] != 0x45)
            {
                return VERIFY_FUNERROR;//功能码错误
            }
            else if (DrvWlConGetBCC(buf, length) != buf[buf.Length - 2])
            {
                return VERIFY_BCCERROR;// 校验错误 
            }
            else
            {
                return VERIFY_NOERROR;
            }
        }

        /// <summary>
        /// 取异或校验码
        /// </summary>
        /// <param name="buf">数据缓冲区</param>
        /// <param name="length">异或效验长度</param>
        /// <returns>返回异或效验的值</returns>
        public static byte DrvWlConGetBCC(byte[] buf, int length)
        {
            int bcc = 0, i = 0;
            for (i = 0; i < length; i++)
            {
                bcc = bcc ^ (buf[i]);
            }
            return Convert.ToByte(bcc);
        }
        #endregion

        #region 初始化

        /// <summary>
        /// AGV叫料串口初始化
        /// </summary>
        private void CallCOMInit()
        {
            int callcombaudrate = int.Parse(ConfigurationManager.AppSettings["CallCOMBaudrate"]);
            int callcomdatabits = int.Parse(ConfigurationManager.AppSettings["CallCOMDataBits"]);
            string callcomstopbits = ConfigurationManager.AppSettings["CallCOMStopBits"];
            string callcomparity = ConfigurationManager.AppSettings["CallCOMParity"];
            try
            {
                SPComCall = new COM.SerialPortWrapper(GlobalPara.GCallcomname, callcombaudrate, callcomparity, callcomdatabits, callcomstopbits);
                SPComCall.OnDataReceived += new SerialDataReceivedEventHandler(SPComCall_OnDataReceived);
            }
            catch (System.Exception ex)
            {
                MessageBox.Show(ex.Message);
                return;
            }
        }

        /// <summary>
        /// agv表格绑定数据初始化
        /// </summary>
        /// <param name="agvnum"></param>
        public void AGVCallScreenInit()
        {
            dataGrid.DataContext = memberData;
        }

        #endregion

        #region 界面操作响应
        /// <summary>
        /// 启动系统
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnStart_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (SPComCall == null)
                {
                    CallCOMInit();
                }
                if (!SPComCall.IsOpen)
                {
                    SPComCall.portname = GlobalPara.GCallcomname;
                    SPComCall.Open();
                }
            }
            catch (System.UnauthorizedAccessException ex)
            {
                MessageBox.Show(ex.Message + "请先暂停此系统或其他系统使用当前串口!", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            catch (System.IO.IOException ex)
            {
                MessageBox.Show(ex.Message + "请在<通信设置>中设置新的串口!", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (SPComCall.IsOpen)
            {
                imgCOM.Source = new BitmapImage(new Uri("pack://application:,,,/Image/Light_Open_24.png"));
                lblcomstate.Content = "打开";
                lblcomstate.Foreground = Brushes.Green;
            }
            lblsystemstate.Content = "打开";
            lblsystemstate.Foreground = Brushes.Green;
            imgSystem.Source = new BitmapImage(new Uri("pack://application:,,,/Image/Light_Open_24.png"));
            btnStart.IsEnabled = false;
            btnEnd.IsEnabled = true;
        }

        /// <summary>
        /// 关闭系统
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnEnd_Click(object sender, RoutedEventArgs e)
        {
            SPComCall.Close();
            if (!SPComCall.IsOpen)
            {
                imgCOM.Source = new BitmapImage(new Uri("pack://application:,,,/Image/Light_Close_24.png"));
                lblcomstate.Content = "关闭";
                lblcomstate.Foreground = Brushes.Red;
            }
            lblsystemstate.Content = "关闭";
            lblsystemstate.Foreground = Brushes.Red;
            imgSystem.Source = new BitmapImage(new Uri("pack://application:,,,/Image/Light_Close_24.png"));
            btnStart.IsEnabled = true;
            btnEnd.IsEnabled = false;
        }

        /// <summary>
        /// 删除记录
        /// </summary>
        /// <param name="strTaskID">流水作业号</param>
        private void DeleteRowFromTaskID(int id)
        {
            bool bFind = memberData.Any<AGV_CALLMember>(p => p.iNO == id);
            if (bFind)
            {
                IEnumerable<AGV_CALLMember> deletemember1 = memberData.Where<AGV_CALLMember>(p => p.iNO == id);
                AGV_CALLMember member1 = deletemember1.First<AGV_CALLMember>();
                Dispatcher.Invoke(new DeleteCallMemberEvent(this.DeleteCallMember), member1);
                IEnumerable<AGV_CALLMember> deletemember2 = memberData.Where<AGV_CALLMember>(p => p.iNO > id);
                foreach (var item in deletemember2)
                {
                    int iIndex = memberData.IndexOf(item);
                    if (iIndex > -1)
                    {
                        memberData[iIndex].iNOValue = memberData[iIndex].iNO - 1;
                    }
                }
            }
        }

        /// <summary>
        /// 删除记录
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnDeleteRecord_Click(object sender, RoutedEventArgs e)
        {
            string id = (sender as Button).CommandParameter.ToString();
            DeleteRowFromTaskID(Convert.ToInt32(id));
        }

        /// <summary>
        /// 记录排队顺序上升
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnUpRecord_Click(object sender, RoutedEventArgs e)
        {
            int id = Convert.ToInt32((sender as Button).CommandParameter.ToString());
            bool bFind = memberData.Any<AGV_CALLMember>(p => p.iNO == id);
            if (bFind)
            {
                IEnumerable<AGV_CALLMember> deletemember1 = memberData.Where<AGV_CALLMember>(p => p.iNO == id);
                AGV_CALLMember member1 = deletemember1.First<AGV_CALLMember>();
                int iIndex = memberData.IndexOf(member1);
                if (iIndex > 0)
                {
                    memberData.Move(iIndex, iIndex - 1);
                }
            }
        }

        /// <summary>
        /// 记录排队顺序下降
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnDownRecord_Click(object sender, RoutedEventArgs e)
        {
            int id = Convert.ToInt32((sender as Button).CommandParameter.ToString());
            bool bFind = memberData.Any<AGV_CALLMember>(p => p.iNO == id);
            if (bFind)
            {
                IEnumerable<AGV_CALLMember> deletemember1 = memberData.Where<AGV_CALLMember>(p => p.iNO == id);
                AGV_CALLMember member1 = deletemember1.First<AGV_CALLMember>();
                int iIndex = memberData.IndexOf(member1);
                if (iIndex >= 0 && (iIndex + 1) < memberData.Count)
                {
                    memberData.Move(iIndex, iIndex + 1);
                }
            }
        }

        #endregion

        #region 菜单栏消息响应
        private void COM_Click(object sender, RoutedEventArgs e)
        {
            CallCOMSetting csdialog = new CallCOMSetting();
            csdialog.Show();
        }

        private void Help_Click(object sender, RoutedEventArgs e)
        {
            Help hdialog = new Help();
            hdialog.Show();
        }

        private void UserManage_Click(object sender, RoutedEventArgs e)
        {
            UserManage umdialog = new UserManage();
            umdialog.Show();
        }

        private void PassWord_Click(object sender, RoutedEventArgs e)
        {
            PassWordSetting psdialog = new PassWordSetting();
            psdialog.Show();
        }

        private void CallManage_Click(object sender, RoutedEventArgs e)
        {
            MaterialsSettings msdialog = new MaterialsSettings();
            msdialog.Show();
        }

        private void CallAddressSet_Click(object sender, RoutedEventArgs e)
        {
            CallAddressSet csdialog = new CallAddressSet();
            csdialog.Show();
        }
        #endregion

        #region 窗体的创建与销毁

        /// <summary>
        /// 窗体构造
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();
            //获取配置文件中的叫料系统串口端口号
            GlobalPara.GCallcomname = ConfigurationManager.AppSettings["CallCOMName"];
            //菜单栏权限设置
            if (!GlobalPara.IsManager)
            {
                MenuSystemSetting.Visibility = Visibility.Collapsed;
                MenuSettings.Visibility = Visibility.Collapsed;
                MenuSystemManage.Visibility = Visibility.Collapsed;
            }
            //状态栏
            lblusername.Content = GlobalPara.strName;
        }

        /// <summary>
        /// 窗体加载
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            AGVCallScreenInit();//表格初始化
            LaunchTimer();//状态栏时间运行
        }

        /// <summary>
        /// Execute shutdown tasks
        /// </summary>
        /// <param name="sender">Object sending the event</param>
        /// <param name="e">Event arguments</param>
        private void Window_Closing(object sender, CancelEventArgs e)
        {
            // Stop Com,Unregister SPComCall data received event
            if (null != SPComCall)
            {
                SPComCall.Close();
                SPComCall.OnDataReceived -= this.SPComCall_OnDataReceived;
            }
            //close & clear SQL
            if (null != callSql)
            {
                callSql.Close();
                callSql = null;
            }
            //clear collection
            if (null != memberData)
            {
                memberData.Clear();
                memberData = null;
            }
            if (null != buf_callctl)
            {
                buf_callctl = null;
            }
            if (null != buf_callret)
            {
                buf_callret = null;
            }
        }
        #endregion
    }
}
