// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using System;

namespace FinderOuter.ViewModels
{
    public class MessageBoxViewModel : ViewModelBase
    {
        public MessageBoxViewModel()
        {
            Message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et " +
                      $"dolore magna aliqua. {Environment.NewLine}Ut enim ad minim veniam, quis nostrud exercitation ullamco " +
                      $"laboris nisi ut aliquip ex ea commodo consequat.";
            IsDualCommand = true;
            CommandName1 = "cmd1";
            CommandName2 = "cmd2";
        }

        public MessageBoxViewModel(MessageBoxType t, string message)
        {
            Message = message;
            msgType = t;
            switch (t)
            {
                case MessageBoxType.Ok:
                    CommandName1 = "Ok";
                    IsDualCommand = false;
                    break;
                case MessageBoxType.OkCancel:
                    CommandName1 = "OK";
                    CommandName2 = "Cancel";
                    IsDualCommand = true;
                    break;
                case MessageBoxType.YesNo:
                    CommandName1 = "Yes";
                    CommandName2 = "No";
                    IsDualCommand = true;
                    break;
                default:
                    throw new NotImplementedException();
            }
        }


        private readonly MessageBoxType msgType;
        public string Message { get; }
        public bool IsDualCommand { get; }
        public string CommandName1 { get; }
        public string CommandName2 { get; }

        public MessageBoxResult Result { get; private set; }

        public void Command1()
        {
            Result = msgType switch
            {
                MessageBoxType.Ok => MessageBoxResult.Ok,
                MessageBoxType.OkCancel => MessageBoxResult.Ok,
                MessageBoxType.YesNo => MessageBoxResult.Yes,
                _ => throw new NotImplementedException(),
            };

            RaiseCloseEvent();
        }

        public void Command2()
        {
            Result = msgType switch
            {
                MessageBoxType.Ok => throw new Exception("This should never happen."),
                MessageBoxType.OkCancel => MessageBoxResult.Cancel,
                MessageBoxType.YesNo => MessageBoxResult.No,
                _ => throw new NotImplementedException(),
            };

            RaiseCloseEvent();
        }
    }
}
