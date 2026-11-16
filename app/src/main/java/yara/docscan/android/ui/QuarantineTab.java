package yara.docscan.android.ui;

import android.app.Activity;
import android.text.format.DateUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;

import yara.docscan.android.R;
import yara.docscan.android.scan.Quarantine;

/** "Карантин": backups of cured documents and quarantined files - restore or delete. */
public final class QuarantineTab {
    private final Activity a;
    private final ExecutorService bg;
    private final Quarantine q;
    private final TextView empty;
    private final Adapter adapter = new Adapter();

    public QuarantineTab(Activity a, View root, ExecutorService bg) {
        this.a = a;
        this.bg = bg;
        this.q = new Quarantine(a);
        root.findViewById(R.id.filter).setVisibility(View.GONE);
        empty = root.findViewById(R.id.empty);
        RecyclerView list = root.findViewById(R.id.list);
        list.setLayoutManager(new LinearLayoutManager(a));
        list.setAdapter(adapter);
    }

    public void refresh() {
        bg.execute(() -> {
            List<Quarantine.Entry> entries = q.list();
            a.runOnUiThread(() -> {
                adapter.set(entries);
                empty.setVisibility(entries.isEmpty() ? View.VISIBLE : View.GONE);
                empty.setText(R.string.quarantine_empty);
            });
        });
    }

    private void restore(Quarantine.Entry e) {
        new AlertDialog.Builder(a)
                .setMessage(a.getString(R.string.quarantine_restore_confirm, e.summary))
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.quarantine_restore, (d, w) -> bg.execute(() -> {
                    String msg;
                    try {
                        q.restore(e);
                        msg = a.getString(R.string.quarantine_restored, e.originalPath);
                    } catch (Exception ex) {
                        msg = ex.getMessage();
                    }
                    String m = msg;
                    a.runOnUiThread(() -> {
                        Toast.makeText(a, m, Toast.LENGTH_LONG).show();
                        refresh();
                    });
                }))
                .show();
    }

    private final class Adapter extends RecyclerView.Adapter<JournalTab.Holder> {
        private final List<Quarantine.Entry> items = new ArrayList<>();

        void set(List<Quarantine.Entry> e) {
            items.clear();
            items.addAll(e);
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public JournalTab.Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new JournalTab.Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_event, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull JournalTab.Holder h, int pos) {
            Quarantine.Entry e = items.get(pos);
            Ui.badge(h.badge, e.verdict.isEmpty() ? "?" : e.verdict);
            h.title.setText(e.originalPath.isEmpty() ? e.copy.getName() : new File(e.originalPath).getName());
            h.summary.setText(e.action + (e.summary.isEmpty() ? "" : " · " + e.summary));
            h.meta.setText(DateUtils.getRelativeTimeSpanString(e.time) + " · "
                    + a.getString(R.string.quarantine_from, e.originalPath));
            View actions = h.itemView.findViewById(R.id.actions);
            actions.setVisibility(View.VISIBLE);
            Button restore = h.itemView.findViewById(R.id.action1);
            Button delete = h.itemView.findViewById(R.id.action2);
            restore.setText(R.string.quarantine_restore);
            restore.setEnabled(!e.originalPath.isEmpty());
            restore.setOnClickListener(v -> restore(e));
            delete.setText(R.string.quarantine_delete);
            delete.setOnClickListener(v -> bg.execute(() -> {
                q.delete(e);
                a.runOnUiThread(QuarantineTab.this::refresh);
            }));
        }

        @Override
        public int getItemCount() {
            return items.size();
        }
    }
}
