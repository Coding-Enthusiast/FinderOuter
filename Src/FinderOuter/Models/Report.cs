// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using ReactiveUI;

namespace FinderOuter.Models
{
	public enum State
	{
		Ready,
		Working,
		Paused,
		Stopped,
		FinishedSuccess,
		FinishedFail
	}

	public class Report : ReactiveObject
	{
		private State _state;
		public State CurrentState
		{
			get => _state;
			set => this.RaiseAndSetIfChanged(ref _state, value);
		}


		private string _msg;
		public string Message
		{
			get => _msg;
			set => this.RaiseAndSetIfChanged(ref _msg, value);
		}

	}
}
