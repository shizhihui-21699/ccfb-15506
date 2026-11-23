defmodule SafeFinder.Demo do
  @moduledoc """
  Runnable end-to-end demonstration of the anti-stalking pipeline.

  Run with:

      mix run demo/anti_stalking_demo.exs

  It walks four scenarios against isolated in-memory processes and prints what
  the victim would experience. No external services are required.
  """

  alias SafeFinder.{
    Alerts,
    Pipeline,
    Types
  }

  alias Types.Observation

  @stops [
    {31.2304, 121.4737},
    {31.2380, 121.4800},
    {31.2460, 121.4870},
    {31.2540, 121.4940},
    {31.2620, 121.5010}
  ]

  def run do
    line("=")
    IO.puts("SafeFinder 防跟踪检测演示")
    line("=")

    scenario_1_covert_tracking()
    scenario_2_family_companion()
    scenario_3_tag_rotation()
    scenario_4_other_brand_phone()

    line("=")
    IO.puts("演示结束")
  end

  # --- scenarios ------------------------------------------------------------

  defp scenario_1_covert_tracking do
    header("场景 1：陌生标签被藏进背包，跟随一人跨城移动")
    pipe = new_pipeline(1_700_000_000)

    traces =
      feed(pipe, trip("ble-covert", "victim-a", 10, accompanied?: false), %{},
        clock: true
      )

    issued = Enum.filter(traces, &match?({:issued, _, _}, &1.result))
    last = List.last(traces)

    IO.puts("最终严重度：#{inspect(last.severity)}，置信度：#{Float.round(last.confidence, 3)}")
    IO.puts("共发出告警数：#{length(issued)}（其余被去重/限流，不轰炸用户）")

    {:issued, alert, payload} = Enum.find_value(issued, &issued_tuple/1)
    IO.puts("告警投递方式：#{alert.delivery}")
    IO.puts("载荷是否含所有者身份：#{payload.owner != nil}（应为 false）")
    IO.puts("载荷是否含精确位置：#{payload.precise_locations != nil}（应为 false）")
  end

  defp scenario_2_family_companion do
    header("场景 2：家人同行——所有者设备在场，应静默")
    pipe = new_pipeline(1_700_000_000)

    traces =
      feed(pipe, trip("ble-family", "victim-b", 10, accompanied?: true), %{},
        clock: true
      )

    last = List.last(traces)
    IO.puts("抑制依据：#{inspect(last.suppression)}")
    IO.puts("是否发出告警：#{match?({:issued, _, _}, last.result)}（应为 false）")
  end

  defp scenario_3_tag_rotation do
    header("场景 3：跟踪者中途更换标签——证据应继承、时间线连续")
    pipe = new_pipeline(1_700_000_000)

    trip_a = trip("ble-tag-A", "victim-c", 7, accompanied?: false, interval: 3600)
    feed(pipe, trip_a, %{owner_account: "stalker-acct"}, clock: true)

    last_a = List.last(trip_a)

    trip_b =
      for i <- 0..4 do
        %Observation{
          tag_pseudonym: "ble-tag-B",
          victim_pseudonym: "victim-c",
          observed_at: last_a.observed_at + 600 + i * 3600,
          lat: last_a.lat,
          lng: last_a.lng,
          finder_epid: "f-#{i}",
          owner_device_present?: false,
          rssi: -60
        }
      end

    traces_b = feed(pipe, trip_b, %{owner_account: "stalker-acct"}, clock: true)
    linked = Enum.find(traces_b, &match?({:linked, _}, &1.rotation))

    IO.puts("是否检测到标签轮换关联：#{linked != nil}")
    if linked, do: IO.puts("关联方式：#{inspect(linked.rotation)}")

    {pipe_pid, _} = pipe
    cluster = Pipeline.cluster(pipe_pid, "victim-c", "ble-tag-B")
    IO.puts("后继标签继承的前驱：#{inspect(cluster.linked_from)}")
    IO.puts("合并后无陪伴观测总数：#{cluster.unaccompanied_count}（A 与 B 累计）")
  end

  defp scenario_4_other_brand_phone do
    header("场景 4：受害者用别家品牌手机、未装 App")
    pipe = new_pipeline(1_700_000_000)

    traces =
      feed(pipe, trip("ble-foreign", "victim-d", 10, accompanied?: false), %{
        victim_profile: %{app_installed?: false}
      }, clock: true)

    issued = Enum.filter(traces, &match?({:issued, _, _}, &1.result))
    {:issued, alert, payload} = Enum.find_value(issued, &issued_tuple/1)

    IO.puts("选择的投递通道：#{alert.delivery}（应为 :platform_payload 系统互通）")
    IO.puts("互通规范版本：#{payload.spec_version}")
    IO.puts("中立指引地址：#{payload.tag.instruction_url}")
  end

  # --- helpers --------------------------------------------------------------

  defp new_pipeline(start_t) do
    # Anonymous, isolated processes so the demo never collides with the
    # application's registered supervision tree.
    {:ok, alerts} = Alerts.start_link(name: nil)
    {:ok, clock} = Agent.start_link(fn -> start_t end)

    {:ok, pipe} =
      Pipeline.start_link(
        name: nil,
        now_fun: fn -> Agent.get(clock, & &1) end,
        alerts_pid: alerts
      )

    {pipe, clock}
  end

  defp feed({pipe, clock}, observations, meta, opts) do
    Enum.map(observations, fn obs ->
      if opts[:clock], do: Agent.update(clock, fn _ -> obs.observed_at end)
      Pipeline.ingest(pipe, obs, meta)
    end)
  end

  defp trip(tag, victim, n, opts) do
    interval = Keyword.get(opts, :interval, 3600)
    accompanied? = Keyword.get(opts, :accompanied?, false)
    start = 1_700_000_000

    for i <- 0..(n - 1) do
      {lat, lng} = Enum.at(@stops, rem(i, length(@stops)))

      %Observation{
        tag_pseudonym: tag,
        victim_pseudonym: victim,
        observed_at: start + i * interval,
        lat: lat,
        lng: lng,
        finder_epid: "finder-#{i}",
        owner_device_present?: accompanied?,
        rssi: -60
      }
    end
  end

  defp issued_tuple(trace) do
    case trace.result do
      {:issued, _alert, _payload} = tuple -> tuple
      _ -> nil
    end
  end

  defp header(text), do: IO.puts("\n## #{text}")
  defp line(char), do: String.duplicate(char, 60) |> IO.puts()
end

SafeFinder.Demo.run()
